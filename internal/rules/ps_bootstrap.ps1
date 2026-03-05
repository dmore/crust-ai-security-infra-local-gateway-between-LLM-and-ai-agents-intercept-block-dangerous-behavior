using namespace System.Management.Automation.Language
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

while ($true) {
    $ln = [Console]::In.ReadLine()
    if ($null -eq $ln) { break }
    try {
        $req  = $ln | ConvertFrom-Json
        $errs = [ParseError[]]@()
        $toks = [Token[]]@()
        $ast  = [Parser]::ParseInput($req.command, [ref]$toks, [ref]$errs)

        $vars   = @{}
        $htVars = @{}
        $objVars = @{}
        $cmds = [System.Collections.Generic.List[object]]::new()
        $addExp = {param($e,$tg)$nx=@($e.NestedExpressions);if($nx.Count-eq 0){$tg.Add($e.Value)}elseif($nx.Count-eq 1-and$nx[0]-is[VariableExpressionAst]){$k=$nx[0].VariablePath.UserPath;if($vars.ContainsKey($k)){$tg.Add($vars[$k])}}}
        foreach ($block in @($ast.BeginBlock, $ast.ProcessBlock, $ast.EndBlock)) {
            if ($null -eq $block) { continue }
            foreach ($stmt in $block.Statements) {
                # Record $var = "literal" and $var = @{Key="value"} assignments.
                if ($stmt -is [AssignmentStatementAst]) {
                    try {
                        $lhs = $stmt.Left
                        $rhs = $stmt.Right
                        $vn = if ($lhs -is [VariableExpressionAst]) { $lhs.VariablePath.UserPath }
                              elseif ($lhs -is [ConvertExpressionAst] -and $lhs.Child -is [VariableExpressionAst]) { $lhs.Child.VariablePath.UserPath }
                        if ($vn) {
                            if ($rhs -is [CommandExpressionAst] -and $rhs.Expression -is [StringConstantExpressionAst]) {
                                $vars[$vn] = $rhs.Expression.Value
                            } elseif ($rhs -is [CommandExpressionAst] -and $rhs.Expression -is [HashtableAst]) {
                                $hv = [System.Collections.Generic.List[string]]::new()
                                foreach ($kvp in $rhs.Expression.KeyValuePairs) {
                                    $kvp.Item2.FindAll({ param($n) $n -is [StringConstantExpressionAst] }, $false) | ForEach-Object { $hv.Add($_.Value) }
                                }
                                $htVars[$vn] = $hv.ToArray()
                            } elseif ($rhs -is [PipelineAst] -and $rhs.PipelineElements.Count -eq 1 -and $rhs.PipelineElements[0] -is [CommandAst]) {
                                $c = $rhs.PipelineElements[0]
                                if ($c.GetCommandName() -ieq 'New-Object' -and $c.CommandElements.Count -ge 2 -and $c.CommandElements[1] -is [StringConstantExpressionAst]) {
                                    $objVars[$vn] = $c.CommandElements[1].Value.ToLower()
                                }
                            }
                        }
                    } catch { $null = $_ }
                }
                # CommandAst nodes (cmdlets) — recurse into nested scriptblocks.
                $stmt.FindAll({ param($n) $n -is [CommandAst] }, $true) | ForEach-Object {
                    $nm = $_.GetCommandName()
                    if (-not $nm) { $fe=$_.CommandElements[0]; if ($fe -is [VariableExpressionAst]) { $k=$fe.VariablePath.UserPath; if ($vars.ContainsKey($k)) { $nm=$vars[$k] } } }
                    if ($nm) {
                        $ag = [System.Collections.Generic.List[string]]::new()
                        $_.CommandElements | Select-Object -Skip 1 | ForEach-Object {
                            try {
                                if ($_ -is [StringConstantExpressionAst]) {
                                    $ag.Add($_.Value)
                                } elseif ($_ -is [VariableExpressionAst]) {
                                    $k = $_.VariablePath.UserPath
                                    if ($_.Splatted) { if ($htVars.ContainsKey($k)) { foreach ($v in $htVars[$k]) { $ag.Add($v) } } }
                                    else { if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) } }
                                } elseif ($_ -is [ExpandableStringExpressionAst]) {
                                    & $addExp $_ $ag
                                } elseif ($_ -is [ArrayExpressionAst] -or $_ -is [ArrayLiteralAst]) {
                                    # Extract literal strings; $false: don't descend into $(cmd) subexpressions.
                                    $_.FindAll({ param($n) $n -is [StringConstantExpressionAst] }, $false) |
                                        ForEach-Object { $ag.Add($_.Value) }
                                } elseif ($_ -is [CommandParameterAst]) {
                                    $ag.Add('-' + $_.ParameterName)
                                    if ($null -ne $_.Argument) {
                                        if ($_.Argument -is [StringConstantExpressionAst]) {
                                            $ag.Add($_.Argument.Value)
                                        } elseif ($_.Argument -is [VariableExpressionAst]) {
                                            $k = $_.Argument.VariablePath.UserPath
                                            if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                        } elseif ($_.Argument -is [ExpandableStringExpressionAst]) {
                                            & $addExp $_.Argument $ag
                                        } elseif ($_.Argument -is [ArrayExpressionAst] -or
                                                  $_.Argument -is [ArrayLiteralAst]) {
                                            $_.Argument.FindAll({ param($n) $n -is [StringConstantExpressionAst] }, $false) |
                                                ForEach-Object { $ag.Add($_.Value) }
                                        }
                                    }
                                }
                            } catch { $null = $_ }
                        }
                        # Pipeline input: "/path" | Get-Content → treat preceding string
                        # expressions (CommandExpressionAst) as implicit positional args.
                        $pp = $_.Parent
                        if ($pp -is [PipelineAst]) {
                            $ix = [array]::IndexOf([object[]]$pp.PipelineElements, $_)
                            for ($i = 0; $i -lt $ix; $i++) {
                                $seg = $pp.PipelineElements[$i]
                                if ($seg -is [CommandExpressionAst]) {
                                    $e = $seg.Expression
                                    try {
                                        if ($e -is [StringConstantExpressionAst]) {
                                            $ag.Add($e.Value)
                                        } elseif ($e -is [ExpandableStringExpressionAst]) {
                                            & $addExp $e $ag
                                        } elseif ($e -is [VariableExpressionAst]) {
                                            $k = $e.VariablePath.UserPath
                                            if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                        }
                                    } catch { $null = $_ }
                                }
                            }
                        }
                        # Redirect paths: > out.txt or < in.txt
                        $redirOut = [System.Collections.Generic.List[string]]::new()
                        $redirIn  = [System.Collections.Generic.List[string]]::new()
                        foreach ($r in $_.Redirections) {
                            try {
                                $f = $r.File
                                if ($f -is [StringConstantExpressionAst]) {
                                    if ($r.FromStream -eq [RedirectionStream]::Input) {
                                        $redirIn.Add($f.Value)
                                    } else {
                                        $redirOut.Add($f.Value)
                                    }
                                }
                            } catch { $null = $_ }
                        }
                        $hasSubst = $false
                        foreach ($el in ($_.CommandElements | Select-Object -Skip 1)) {
                            if ($el -isnot [StringConstantExpressionAst] -and
                                $el -isnot [CommandParameterAst]) {
                                $hasSubst = $true; break
                            }
                            if ($el -is [CommandParameterAst] -and
                                $null -ne $el.Argument -and
                                $el.Argument -isnot [StringConstantExpressionAst]) {
                                $hasSubst = $true; break
                            }
                        }
                        $cmds.Add([PSCustomObject]@{
                            name           = $nm
                            args           = [string[]]$ag.ToArray()
                            redir_paths    = [string[]]$redirOut.ToArray()
                            redir_in_paths = [string[]]$redirIn.ToArray()
                            has_subst      = $hasSubst
                        })
                    }
                }
                # .NET static calls: [Type]::Method(args) — emitted as "Type::Method".
                # Go normalizes names containing '::' to lowercase for DB lookup.
                $stmt.FindAll({param($n)$n-is[InvokeMemberExpressionAst]-and$n.Static},$true)|ForEach-Object{try{if($_.Expression-is[TypeExpressionAst]-and$_.Member-is[StringConstantExpressionAst]){$da=[System.Collections.Generic.List[string]]::new();foreach($a in $_.Arguments){if($a-is[StringConstantExpressionAst]){$da.Add($a.Value)}};$cmds.Add([PSCustomObject]@{name=$_.Expression.TypeName.FullName+'::'+$_.Member.Value;args=[string[]]$da.ToArray();redir_paths=[string[]]@();redir_in_paths=[string[]]@();has_subst=$false})}}catch{$null=$_}}
                $stmt.FindAll({param($n)$n-is[InvokeMemberExpressionAst]-and-not$n.Static},$true)|ForEach-Object{try{$tn=$null;if($_.Expression-is[VariableExpressionAst]){$k=$_.Expression.VariablePath.UserPath;if($objVars.ContainsKey($k)){$tn=$objVars[$k]}}elseif($_.Expression-is[ParenExpressionAst]){$ip=$_.Expression.Pipeline;if($ip-is[PipelineAst]-and$ip.PipelineElements.Count-eq 1-and$ip.PipelineElements[0]-is[CommandAst]){$ic=$ip.PipelineElements[0];if($ic.GetCommandName()-ieq'New-Object'-and$ic.CommandElements.Count-ge 2-and$ic.CommandElements[1]-is[StringConstantExpressionAst]){$tn=$ic.CommandElements[1].Value.ToLower()}}};if($tn-and$_.Member-is[StringConstantExpressionAst]){$da=[System.Collections.Generic.List[string]]::new();$hs=$false;foreach($a in $_.Arguments){if($a-is[StringConstantExpressionAst]){$da.Add($a.Value)}elseif(-not $hs){$hs=$true}};$cmds.Add([PSCustomObject]@{name=$tn+'::'+$_.Member.Value;args=[string[]]$da.ToArray();redir_paths=[string[]]@();redir_in_paths=[string[]]@();has_subst=$hs})}}catch{$null=$_}}
            }
        }

        $resp = [PSCustomObject]@{
            commands    = [object[]]$cmds.ToArray()
            parseErrors = [string[]]@($errs | ForEach-Object { $_.Message })
        }
        # Strip newlines: response must be exactly one line for bufio.Scanner.
        ($resp | ConvertTo-Json -Compress -Depth 5) -replace '\r\n|\r|\n', ''
        [Console]::Out.Flush()
    } catch {
        ([PSCustomObject]@{
            commands    = [object[]]@()
            parseErrors = [string[]]@($_.Exception.Message)
        } | ConvertTo-Json -Compress) -replace '\r\n|\r|\n', ''
        [Console]::Out.Flush()
    }
}
