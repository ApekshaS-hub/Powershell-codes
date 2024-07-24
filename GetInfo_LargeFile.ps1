# Define the threshold size in bytes (10MB)
$threshold = 10MB

# Function to get large files recursively with error handling
function Get-LargeFiles {
    param (
        [string]$path
    )
    try {
        Get-ChildItem -Path $path -Recurse -File -ErrorAction Stop | Where-Object { $_.Length -gt $threshold }
    } catch {
        Write-Output "Skipping directory: $path due to access denied."
    }
}

# Get all files larger than the threshold and sort them in descending order by size
$largeFiles = Get-LargeFiles -path "C:\" | Sort-Object -Property Length -Descending

# Display the results
$largeFiles | Select-Object Name, @{Name="ModifiedDate";Expression={$_.LastWriteTime.ToString("yyyy-MM-dd")}}, @{Name="SizeMB";Expression={[math]::round($_.Length / 1MB, 2)}}, FullName | Format-Table -AutoSize
