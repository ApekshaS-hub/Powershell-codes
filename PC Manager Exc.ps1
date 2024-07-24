#**************************Storage - All Files in downloaded folder OR Top 10 Files in downloaded folder **************************************

# Define the path to the Downloads folder
#$DownloadsFolder = "C:\Users\a835062\Downloads"
$DownloadsFolder = "$env:userprofile\Downloads"


<## Retrieve and sort files, then select the top 10 largest
$TopFiles = Get-ChildItem -Path $DownloadsFolder -File -Recurse | 
    Sort-Object -Property Length -Descending | 
    Select-Object -First 10#>


# Retrieve and sort all files by size in descending order
$AllFiles = Get-ChildItem -Path $DownloadsFolder -File -Recurse | 
    Sort-Object -Property Length -Descending

# Create a custom object array to store the results
$FileList = @()

# Populate the custom object array with file details
foreach ($file in $AllFiles) {
    $FileDetails = [PSCustomObject]@{
        Name = $file.Name
        SizeMB = [Math]::Round(($file.Length / 1MB), 2)
        FullPath = $file.FullName
        ModifiedDate = $file.LastWriteTime.ToString("yyyy-MM-dd")
    }
    $FileList += $FileDetails
}

# Output the results as a formatted table
$FileList | Format-Table -Property Name, ModifiedDate, SizeMB, FullPath -AutoSize | Out-String -Width 4096




#****************************************Storage - Top 10 Large Files for PC**************************************

# Define the path to the root of the file system
$RootFolder = "C:\"

# Retrieve and sort all files by size in descending order
$AllFiles = Get-ChildItem -Path $RootFolder -File -Recurse -ErrorAction SilentlyContinue | 
    Sort-Object -Property Length -Descending | 
    Select-Object -First 10

# Create a custom object array to store the results
$FileList = @()

# Populate the custom object array with file details
foreach ($file in $AllFiles) {
    $FileDetails = [PSCustomObject]@{
        Name = $file.Name
        SizeMB = [Math]::Round(($file.Length / 1MB), 2)
        FullPath = $file.FullName
        ModifiedDate = $file.LastWriteTime.ToString("yyyy-MM-dd")
    }
    $FileList += $FileDetails
}

# Output the results as a formatted table
$FileList | Format-Table -Property Name, ModifiedDate, SizeMB, FullPath -AutoSize | Out-String -Width 4096


#****************************************Storage - Dupliate Files in PC**************************************

#1)
# Specify the directory to scan
$directoryToScan = "C:\Users\a835062\OneDrive - ATOS"  # Sample path

# Get all files recursively in the specified directory
$files = Get-ChildItem -Path $directoryToScan -File -Recurse

# Group files by their name and size
$groupedFiles = $files | Group-Object Name, Length

# Find duplicate files
$duplicateFiles = $groupedFiles | Where-Object { $_.Count -gt 1 }

$totalDuplicateSize = 0

if ($duplicateFiles.Count -gt 0) {
    Write-Host "Duplicate files found:"
    
    # Prepare objects for formatting
    $output = foreach ($group in $duplicateFiles) {
    Write-Host "Duplicate group:"
        foreach ($file in $group.Group) {
            $totalDuplicateSize += $file.Length
            [PSCustomObject]@{
                Name = $file.Name
                FullPath = $file.FullName
                ModifiedDate = $file.LastWriteTime.ToString("yyyy-MM-dd")
                Size = "{0:N2} MB" -f ($file.Length / 1MB)
            }
        }
    }

    # Format output using Format-Table
    $output | Format-Table -Property Name, FullPath, ModifiedDate, Size -AutoSize | Out-String -Width 4096
        
    Write-Host "---------------------------"
    Write-Host "Total size of duplicate files: $([math]::round($totalDuplicateSize / 1MB, 2)) MB"
} else {
    Write-Host "No duplicate files found in the specified directory."
}
                       
     ################################ORRRRRRRRRRRRRRR############################
#2)
# Specify the directory to scan
$directoryToScan = "C:\Users\a835062\OneDrive - ATOS"  # Sample path


# Get all files recursively in the specified directory
$files = Get-ChildItem -Path $directoryToScan -File -Recurse

# Group files by their name and size
$groupedFiles = $files | Group-Object Name, Length

# Find duplicate files
$duplicateFiles = $groupedFiles | Where-Object { $_.Count -gt 1 }

$totalDuplicateSize = 0

if ($duplicateFiles.Count -gt 0) {
    Write-Host "Duplicate files found:"
    foreach ($group in $duplicateFiles) {
        Write-Host "Duplicate group:"
        foreach ($file in $group.Group) {
            $totalDuplicateSize += $file.Length
            Write-Host ("{0,-40} {1,-25} {2,-10} {3}" -f $file.Name, $file.FullName, $file.LastWriteTime.ToString("yyyy-MM-dd"), ("{0:N2} MB" -f ($file.Length / 1MB)))
        }
        Write-Host "---------------------------"
    }
    Write-Host "Total size of duplicate files: $([math]::round($totalDuplicateSize / 1MB, 2)) MB"
} else {
    Write-Host "No duplicate files found in the specified directory."
}



#**************************************Health-Check****************************************************
<#This script provides a comprehensive overview of the system's health,
covering essential aspects such as disk usage, memory status, CPU utilization, and system uptime,
 helping you monitor and diagnose the health of your system efficiently using PowerShell.#>

# Function to check system health
function Get-SystemHealth {
    try {
        # Get disk usage
        $diskUsage = Get-WmiObject -Class Win32_LogicalDisk |
                     Select-Object DeviceID, VolumeName, @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}, `
                                   @{Name="SizeGB";Expression={[math]::Round($_.Size / 1GB, 2)}}

        # Get memory usage
        $memory = Get-WmiObject -Class Win32_OperatingSystem |
                  Select-Object @{Name="FreeMemoryGB";Expression={[math]::Round($_.FreePhysicalMemory / 1GB, 2)}}, `
                                @{Name="TotalMemoryGB";Expression={[math]::Round($_.TotalVisibleMemorySize / 1GB, 2)}}

        # Get CPU utilization
        $cpu = Get-WmiObject -Class Win32_PerfFormattedData_PerfOS_Processor |
               Where-Object { $_.Name -eq "_Total" } |
               Select-Object Name, @{Name="CPUUsagePercent";Expression={100 - $_.PercentIdleTime}}

        # Get system uptime
        $uptime = Get-WmiObject -Class Win32_OperatingSystem |
                  Select-Object LastBootUpTime, @{Name="UptimeHours";Expression={[math]::Round((Get-Date) - $_.ConvertToDateTime($_.LastBootUpTime)).TotalHours}}

        # Output system health information
        Write-Output "---- System Health Report ----"
        Write-Output "Disk Usage:"
        $diskUsage | Format-Table -AutoSize
        Write-Output ""
        Write-Output "Memory Usage:"
        $memory | Format-Table -AutoSize
        Write-Output ""
        Write-Output "CPU Utilization:"
        $cpu | Format-Table -AutoSize
        Write-Output ""
        Write-Output "System Uptime:"
        $uptime | Format-Table -AutoSize

    } catch {
        Write-Error "Error occurred while retrieving system health information: $_"
    }
}

# Call the function to get system health
Get-SystemHealth



#*****************************************PoP-Up Management*****************************************************

# Function to enable pop-up blocker in Microsoft Edge
function Enable-PopUpBlocker {
    # Define the registry path for Microsoft Edge pop-up blocker setting
    $registryPath = "HKCU:\Software\Policies\Microsoft\Edge"
    $valueName = "PopupsBlocked"

    # Create the registry key if it doesn't exist
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set the value to enable pop-up blocker
    Set-ItemProperty -Path $registryPath -Name $valueName -Value 1
    Write-Output "Pop-up blocker enabled for Microsoft Edge."
}

# Function to disable pop-up blocker in Microsoft Edge
function Disable-PopUpBlocker {
    # Define the registry path for Microsoft Edge pop-up blocker setting
    $registryPath = "HKCU:\Software\Policies\Microsoft\Edge"
    $valueName = "PopupsBlocked"

    # Create the registry key if it doesn't exist
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set the value to disable pop-up blocker
    Set-ItemProperty -Path $registryPath -Name $valueName -Value 0
    Write-Output "Pop-up blocker disabled for Microsoft Edge."
}

# Main script execution
# Uncomment one of the following lines to enable or disable pop-up blockers

# Enable-PopUpBlocker
# Disable-PopUpBlocker


#********************************************************88ORRRRRRRRRRRRRRRRRRR************************************************

# Define the applications for which you want to block pop-up windows
$applications = @(
    "chrome.exe",
    "firefox.exe",
    "iexplore.exe",
    "edge.exe"
)

# Function to kill pop-up windows based on their title
function Kill-Popups {
    param (
        [string]$application,
        [string]$popupTitle
    )

    <# Get the list of all windows || This property contains the title text of the main window associated with a process.
    If the process has a graphical user interface (GUI) with a window, the MainWindowTitle will contain the text displayed in the title bar of that window.
    If the process does not have a main window (such as background or service processes), MainWindowTitle will be an empty string.#>
    $windows = Get-Process | Where-Object { $_.MainWindowTitle -ne "" }

    foreach ($window in $windows) {
        if ($window.ProcessName -eq $application -and $window.MainWindowTitle -like "*$popupTitle*") {
            # Kill the process
            Stop-Process -Id $window.Id -Force
            Write-Host "Killed pop-up window: $($window.MainWindowTitle)"
        }
    }
}

# Define the list of known pop-up titles to block
$popupTitles = @(
    "Advertisement",
    "Survey",
    "Special Offer",
    "Update Available",
    "Notification"
)

# Loop to continuously check and kill pop-up windows
while ($true) {
    foreach ($application in $applications) {
        foreach ($popupTitle in $popupTitles) {
            Kill-Popups -application $application -popupTitle $popupTitle
        }
    }
    # Wait for a few seconds before checking again
    Start-Sleep -Seconds 5
}






