
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
