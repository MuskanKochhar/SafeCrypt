param (
    [string]$Path,
    [string]$Action
)

if (!(Test-Path $Path)) {
    Write-Output "Error: Path not found."
    exit 1
}

try {
    $item = Get-Item $Path -Force

    if ($item.PSIsContainer) {
        $dirInfo = New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $Path
        if ($Action -eq "hide") {
            $dirInfo.Attributes = $dirInfo.Attributes -bor [System.IO.FileAttributes]::Hidden
        } elseif ($Action -eq "unhide") {
            $dirInfo.Attributes = $dirInfo.Attributes -band (-bnot [System.IO.FileAttributes]::Hidden)
        } else {
            Write-Output "Error: Invalid action."
            exit 1
        }
    } else {
        $fileInfo = New-Object -TypeName System.IO.FileInfo -ArgumentList $Path
        if ($Action -eq "hide") {
            $fileInfo.Attributes = $fileInfo.Attributes -bor [System.IO.FileAttributes]::Hidden
        } elseif ($Action -eq "unhide") {
            $fileInfo.Attributes = $fileInfo.Attributes -band (-bnot [System.IO.FileAttributes]::Hidden)
        } else {
            Write-Output "Error: Invalid action."
            exit 1
        }
    }

    exit 0
}
catch {
    Write-Output "Error: $_"
    exit 1
}
