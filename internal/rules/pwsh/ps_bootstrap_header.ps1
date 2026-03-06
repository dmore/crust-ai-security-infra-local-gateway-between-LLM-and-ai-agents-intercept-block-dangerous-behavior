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
        $resolveVar = {param($k,$tg) if($vars.ContainsKey($k)){$tg.Add($vars[$k])}elseif($k-match'^env:(.+)$'){$v=[System.Environment]::GetEnvironmentVariable($Matches[1]);if($null-ne $v){$tg.Add($v)}}}
        $addExp = {param($e,$tg)$nx=@($e.NestedExpressions);if($nx.Count-eq 0){$tg.Add($e.Value)}elseif($nx.Count-eq 1-and$nx[0]-is[VariableExpressionAst]){$k=$nx[0].VariablePath.UserPath;$rv=$null;if($vars.ContainsKey($k)){$rv=$vars[$k]}elseif($k-match'^env:(.+)$'){$rv=[System.Environment]::GetEnvironmentVariable($Matches[1])};if($null-ne $rv){$text=$e.Extent.Text.Trim('"').Trim("'");$tg.Add($text.Replace($nx[0].Extent.Text,$rv))}}}
        foreach ($block in @($ast.BeginBlock, $ast.ProcessBlock, $ast.EndBlock)) {
            if ($null -eq $block) { continue }
            foreach ($stmt in $block.Statements) {
                # Record $var = "literal" and $var = @{Key="value"} assignments.
                if ($stmt -is [AssignmentStatementAst]) {
