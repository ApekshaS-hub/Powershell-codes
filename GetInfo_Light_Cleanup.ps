################QUE:1 GetInfo- The script calculates the total size of temporary files and the Recycle Bin###################

# Get the total size of temporary files
$TempFolder = [System.IO.Path]::GetTempPath() ##Identifies the path to the temporary files directory using [System.IO.Path]::GetTempPath()
$TempFiles = Get-ChildItem -Path $TempFolder -Recurse -File
$TotalTempSize = ($TempFiles | Measure-Object -Property Length -Sum).Sum / 1MB

# Get the total size of the Recycle Bin
$RecycleBin = New-Object -ComObject Shell.Application #Uses the Shell.Application COM object to access the Recycle Bin
$RecycleBinItems = $RecycleBin.Namespace(0xA).Items()
$TotalRecycleBinSize = 0
foreach ($item in $RecycleBinItems) {
    $TotalRecycleBinSize += $item.Size
}
$TotalRecycleBinSize = $TotalRecycleBinSize / 1MB

# Round the values to 2 decimal places
$TotalTempSizeRounded = [math]::Round($TotalTempSize, 2)
$TotalRecycleBinSizeRounded = [math]::Round($TotalRecycleBinSize, 2)

# Calculate the total size
$TotalSize = $TotalTempSizeRounded + $TotalRecycleBinSizeRounded

# Display the total sizes in the output
Write-Output "Total size of temporary files: $TotalTempSizeRounded MB"
Write-Output "Total size of Recycle Bin: $TotalRecycleBinSizeRounded MB"
Write-Output "Total size: $TotalSize MB"


Write-Output "********************************************************"
