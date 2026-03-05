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
                                if ($c.GetCommandName() -ieq 'New-Object' -and $c.CommandElements.Count -ge 2) {
                                    $tn = $null
                                    if ($c.CommandElements[1] -is [StringConstantExpressionAst]) {
                                        $tn = $c.CommandElements[1].Value
                                    } elseif ($c.CommandElements[1] -is [CommandParameterAst] -and
                                              $c.CommandElements[1].ParameterName -ieq 'TypeName' -and
                                              $c.CommandElements.Count -ge 3 -and
                                              $c.CommandElements[2] -is [StringConstantExpressionAst]) {
                                        $tn = $c.CommandElements[2].Value
                                    }
                                    if ($tn) { $objVars[$vn] = $tn.ToLower() }
                                }
                            }
                        }
                    } catch { $null = $_ }
                }
