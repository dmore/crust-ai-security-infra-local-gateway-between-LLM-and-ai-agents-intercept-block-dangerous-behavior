
        $resp = [PSCustomObject]@{
            commands    = [object[]]$cmds.ToArray()
            parseErrors = [string[]]@($errs | ForEach-Object { $_.Message })
        }
        # Write explicitly via Console.Out.WriteLine rather than relying on
        # PowerShell's implicit output stream (bare expression → OutDefault).
        # On legacy powershell.exe (5.1), implicit output and Console.Out use
        # different buffers; [Console]::Out.Flush() would not flush implicit
        # output, leaving the JSON line in PS's internal buffer and causing
        # Go's bufio.Scanner.Scan() to block indefinitely.
        $json = ($resp | ConvertTo-Json -Compress -Depth 5) -replace '\r\n|\r|\n', ''
        [Console]::Out.WriteLine($json)
        [Console]::Out.Flush()
    } catch {
        $json = ([PSCustomObject]@{
            commands    = [object[]]@()
            parseErrors = [string[]]@($_.Exception.Message)
        } | ConvertTo-Json -Compress) -replace '\r\n|\r|\n', ''
        [Console]::Out.WriteLine($json)
        [Console]::Out.Flush()
    }
}
