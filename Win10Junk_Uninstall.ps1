## Configure the apps to be removed
$AppsList = "Microsoft.BingWeather",                 
            "Microsoft.DesktopAppInstaller",         
            "Microsoft.GetHelp",                     
            "Microsoft.Getstarted",                  
            "Microsoft.Messaging",                   
            "Microsoft.Microsoft3DViewer",           
            "Microsoft.MicrosoftOfficeHub",          
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MicrosoftStickyNotes",        
            "Microsoft.MSPaint",                     
            "Microsoft.Office.OneNote",              
            "Microsoft.OneConnect",                  
            "Microsoft.People",                      
            "Microsoft.Print3D",                     
            "Microsoft.SkypeApp",                    
            "Microsoft.StorePurchaseApp",            
            "Microsoft.Wallet",                      
            "Microsoft.Windows.Photos",              
            "Microsoft.WindowsAlarms",               
            "Microsoft.WindowsCalculator",           
            "Microsoft.WindowsCamera",               
            "microsoft.windowscommunicationsapps",   
            "Microsoft.WindowsFeedbackHub",          
            "Microsoft.WindowsMaps",                 
            "Microsoft.WindowsSoundRecorder",        
            "Microsoft.WindowsStore",                
            "Microsoft.Xbox.TCUI",                   
            "Microsoft.XboxApp",                     
            "Microsoft.XboxGameOverlay",             
            "Microsoft.XboxIdentityProvider",        
            "Microsoft.XboxSpeechToTextOverlay",     
            "Microsoft.ZuneMusic",                   
            "Microsoft.ZuneVideo"
 
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



