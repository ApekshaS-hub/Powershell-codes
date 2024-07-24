# Define the download directories for Edge and Chrome
$edgeDownloadPath = "$env:USERPROFILE\Downloads"
$chromeDownloadPath = "$env:USERPROFILE\Downloads"

# Define the file types to search for
$fileTypes = "*.mp3", "*.mp4", "*.avi", "*.mkv", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.pdf", "*.docx", "*.xlsx"

# Function to get files from a specified path and of specified types
function Get-DownloadedFiles {
    param (
        [string]$path,
        [array]$types
    )
    $files = @()
    foreach ($type in $types) {
        $files += Get-ChildItem -Path $path -Recurse -File -Include $type -ErrorAction SilentlyContinue
    }
    return $files
}

# Get files from Edge and Chrome download directories
$edgeFiles = Get-DownloadedFiles -path $edgeDownloadPath -types $fileTypes
$chromeFiles = Get-DownloadedFiles -path $chromeDownloadPath -types $fileTypes

# Combine the files from both directories, avoiding duplicates
$uniqueFiles = @{}
foreach ($file in $edgeFiles + $chromeFiles) {
    $uniqueFiles[$file.FullName] = $file
}

# Get the unique files and sort them in descending order by size
$allFiles = $uniqueFiles.Values | Sort-Object -Property Length -Descending

# Calculate the total size of the files in MB
$totalSizeMB = [math]::round(($allFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)

# Display the results
$allFiles | Select-Object Name, @{Name="ModifiedDate";Expression={$_.LastWriteTime.ToString("yyyy-MM-dd")}}, @{Name="SizeMB";Expression={[math]::round($_.Length / 1MB, 2)}}, FullName | Format-Table -AutoSize

# Display the total size of downloaded files
Write-Output "Total Size of Downloaded Files: $totalSizeMB MB"
