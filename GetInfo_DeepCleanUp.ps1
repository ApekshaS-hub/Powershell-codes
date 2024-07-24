
function Get-FolderSize {
    param (
        [string]$Path
    )
    
    if (-Not (Test-Path -Path $Path)) {
        Write-Warning "Path $Path does not exist."
        return 0
    }
    
    try {
        $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction Stop
        $totalSize = ($files | Measure-Object -Property Length -Sum).Sum / 1MB
        return [math]::Round($totalSize, 2)
    }
    catch {
        Write-Warning "Failed to get size for path $Path. Error: $_"
        return 0
    }
}

# Paths to the directories
$paths = @{
    "Windows Update Cleanup" = "C:\Windows\SoftwareDistribution\DataStore\Logs"
    "Windows Error Reports and Feedback Diagnostics" = "C:\ProgramData\Microsoft\Windows\WER\ReportArchive"
    "Microsoft Defender Logs and Scan History Files" = "C:\ProgramData\Microsoft\Windows Defender\Support"
    "Temporary Files" = [System.IO.Path]::GetTempPath()
}

$totalSize = 0

# Calculate sizes and display output
foreach ($name in $paths.Keys) {
    $size = Get-FolderSize -Path $paths[$name]
    Write-Output "Total size of {$name}: $size MB"
    $totalSize += $size
}

# Display total size of all directories
Write-Output "Total size of all specified directories: $totalSize MB"

Write-Output "********************************************************"
