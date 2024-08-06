# Define the $paths variable globally
$paths = @{
    "Windows Update Cleanup" = "C:\Windows\SoftwareDistribution\DataStore\Logs"
    "Windows Error Reports and Feedback Diagnostics" = "C:\ProgramData\Microsoft\Windows\WER\ReportArchive"
    "Microsoft Defender Logs and Scan History Files" = "C:\ProgramData\Microsoft\Windows Defender\Support"
    "Temporary Files" = [System.IO.Path]::GetTempPath()
}

function Get-FolderSizes {
    # Access the global $paths variable
    $Paths = $paths

    $totalSize = 0
 
    foreach ($name in $Paths.Keys) {
        if (-Not (Test-Path -Path $Paths[$name])) {
            Write-Warning "Path $($Paths[$name]) does not exist."
            continue
        }
 
        try {
            $files = Get-ChildItem -Path $Paths[$name] -Recurse -File -ErrorAction Stop
            $size = ($files | Measure-Object -Property Length -Sum).Sum / 1MB
            $size = [math]::Round($size, 2)
        }
        catch {
            Write-Warning "Failed to get size for path $($Paths[$name]). Error: $_"
            $size = 0
        }
 
        Write-Output "Total size of ${name}: ${size} MB"
        $totalSize += $size
    }
 
    Write-Output "Total size of all specified directories: ${totalSize} MB"
    Write-Output "********************************************************"
}
 
# Call the function
Get-FolderSizes
