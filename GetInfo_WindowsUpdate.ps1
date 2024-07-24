# Function to check if Windows is up-to-date
function Check-WindowsUpdateStatus {
    # Get the list of installed updates
    $installedUpdates = Get-HotFix

    # Get the list of available updates
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0")

    # Display the update status
    if ($searchResult.Updates.Count -eq 0) {
        Write-Output "Windows is up-to-date."
    } else {
        Write-Output "There are pending updates:"
        $searchResult.Updates | ForEach-Object {
            Write-Output $_.Title
        }
    }
}

# Run the function to check the update status
Check-WindowsUpdateStatus
