# 

 
## Configure the apps to be removed
# add to list use : Get-AppxPackage * | select name

$applist = Import-Csv -path .\apps.txt
 
##Remove the Apps listed above or report if app not present
ForEach ($App in $AppsList)
{
    $PackageFullName = (Get-AppxPackage $App).PackageFullName
 
    If ($PackageFullName)
    {
        Write-Host "Removing Package: $App"
        Remove-AppxPackage -Package $PackageFullName
    }
 
    Else
    {
        Write-Host "Unable to find package: $App"
    }
}
 
## End



