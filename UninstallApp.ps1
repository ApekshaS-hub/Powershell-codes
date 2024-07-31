# Get all installed app packages
$appPackages = Get-AppxPackage

# Create an array of custom objects to hold the data
$appList = $appPackages | ForEach-Object {
    # Determine if the package is system-installed or user-installed
    $installationType = if ($_.PackageFamilyName -like "Microsoft.*") { "System" } else { "User" }

    # Create a custom object for each application
    [PSCustomObject]@{
        Name              = $_.Name
        InstallationType  = $installationType
    }
}

# Get unique applications by grouping on the Name property
$uniqueApps = $appList | Group-Object -Property Name | ForEach-Object {
    # Create a single object for each unique application
    [PSCustomObject]@{
        Name              = $_.Name
        InstallationType  = $_.Group | Select-Object -First 1 -ExpandProperty InstallationType
    }
}

# Display the results in a table format
$uniqueApps | Format-Table -AutoSize

# Output the total number of unique applications
Write-Output "Total number of unique applications: $($uniqueApps.Count)"
