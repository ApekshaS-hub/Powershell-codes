function Get-DownloadedFiles {
    param (
        [array]$Paths,
        [array]$Types
    )
    $files = @()
    foreach ($path in $Paths) {
        foreach ($type in $Types) {
            $files += Get-ChildItem -Path $path -Recurse -File -Include $type -ErrorAction SilentlyContinue
        }
    }

    $uniqueFiles = $files | Group-Object -Property FullName | ForEach-Object { $_.Group[0] }
    $sortedFiles = $uniqueFiles | Sort-Object -Property Length -Descending
    $totalSizeMB = [math]::Round(($sortedFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)

    $sortedFiles | Select-Object Name, @{Name="ModifiedDate";Expression={$_.LastWriteTime.ToString("yyyy-MM-dd")}}, @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}}, FullName | Format-Table -AutoSize
    Write-Output "Total Size of Downloaded Files: $totalSizeMB MB"
}

$paths = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Downloads")
$fileTypes = "*.mp3", "*.mp4", "*.avi", "*.mkv", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.pdf", "*.docx", "*.xlsx"

Get-DownloadedFiles -Paths $paths -Types $fileTypes
