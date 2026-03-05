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
