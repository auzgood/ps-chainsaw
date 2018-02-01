#Load Assemblies (WPF)
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')

#region $ScriptPath Assignment
if (
    $host.name -eq 'ConsoleHost'
    ){
      IF(
         [string]::IsNullOrEmpty($TempDirectory)
         ){
            $ScriptPath = $MyInvocation.MyCommand.Path | split-path -Parent
           }
      }
else {
      IF(
         [string]::IsNullOrEmpty($ScriptPath) -and
         ($host.name -match 'ISE')
         ){
            #region Open Folder Dialog to select $TempDirectory Parameter if not specified.
            Function Select-FolderDialog
                                        {
                                         param([string]$Description="Select Folder",[string]$RootFolder="Desktop")
                                         [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null     
                                         $objForm = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
                                         $objForm.Rootfolder = $RootFolder
                                         $objForm.Description = $Description
                                         $Show = $objForm.ShowDialog()
                                         If (
                                             $Show -eq "OK"
                                             ){
                                                Return $objForm.SelectedPath
                                               }
                                         Else {
                                                Write-Error -Message "Operation cancelled by user."
                                               }
                                          }
            $ScriptPath = Select-FolderDialog
            #endregion Open Folder Dialog to select $TempDirectory Parameter if not specified.
           }
      } 

#endregion $ScriptPath Assignment

#region Helper Functions
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
 
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

function Hide-Console {
    $consolePtr = [Console.Window]::GetConsoleWindow()
  #0 hide
 [Console.Window]::ShowWindow($consolePtr, 0)
}

Function Get-FileName($initialDirectory){   
                                             [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | 
                                             Out-Null
                                             $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                                             $OpenFileDialog.initialDirectory = $initialDirectory
                                             $OpenFileDialog.filter = "XML files (*.xml)| *.xml"
                                             $OpenFileDialog.ShowDialog() | Out-Null
                                             $OpenFileDialog.filename
                                             $OpenFileDialog.Title = "Configuration XML"
                                            }

Function Set-FileName($initialDirectory){   
                                             [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | 
                                             Out-Null
                                             $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                                             $OpenFileDialog.initialDirectory = $initialDirectory
                                             $OpenFileDialog.filter = "PS1 files (*.ps1)| *.ps1"
                                             $OpenFileDialog.ShowDialog() | Out-Null
                                             $OpenFileDialog.filename
                                             $OpenFileDialog.Title = "Save PowerShell Script"
                                            }

Function Set-FileName2($initialDirectory){   
                                             [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | 
                                             Out-Null
                                             $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                                             $OpenFileDialog.initialDirectory = $initialDirectory
                                             $OpenFileDialog.filter = "Text files (*.txt)| *.txt"
                                             $OpenFileDialog.ShowDialog() | Out-Null
                                             $OpenFileDialog.filename
                                             $OpenFileDialog.Title = "Save Encrypted Text"
                                            }

function EncryptString{  
                        param( $SymetricAlgorithm,   
                               [string] $inputString  
                              )  
                        $inputBlock = [System.Text.UnicodeEncoding]::Unicode.getbytes($inputString)  
                        $Transform = $SymetricAlgorithm.CreateEncryptor()  
                        $outputBlock = $Transform.TransformFinalBlock($inputBlock, 0, $inputBlock.Length);  
                        return $outputBlock;  
                        }

function Set-Clipboard{
<#

.SYNOPSIS

Sends the given input to the Windows clipboard.

.EXAMPLE

dir | Set-Clipboard
This example sends the view of a directory listing to the clipboard

.EXAMPLE

Set-Clipboard "Hello World"
This example sets the clipboard to the string, "Hello World".

#>

param(
        ## The input to send to the clipboard
        [Parameter(ValueFromPipeline = $true)]
        [object[]] $InputObject
      )
begin{
        Set-StrictMode -Version Latest
        $objectsToProcess = @()
      }
process{
        ## Collect everything sent to the script either through
        ## pipeline input, or direct input.
        $objectsToProcess += $inputObject
        }
end{
    ## Launch a new instance of PowerShell in STA mode.
    ## This lets us interact with the Windows clipboard.
    $objectsToProcess | PowerShell -NoProfile -STA -Command {
                                                                Add-Type -Assembly PresentationCore
                                                                ## Convert the input objects to a string representation
                                                                $clipText = ($input | Out-String -Stream) -join "`r`n"
                                                                ## And finally set the clipboard text
                                                                [Windows.Clipboard]::SetText($clipText)
                                                             }
    }
}

function Get-SHA1{
param ([String[]]$File)
    $StringBuilder = New-Object System.Text.StringBuilder
    $InputStream = New-Object System.IO.FileStream($File,[System.IO.FileMode]::Open)
    $Provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $Provider.ComputeHash($InputStream) | Foreach-Object { [void]$StringBuilder.Append($_.ToString("X2")) }
    $InputStream.Close()
    return ($StringBuilder.ToString())
}

#endregion elper Functions

Hide-Console

#XAML Code
[xml]$XAML = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AES String Encryption" Height="620" Width="909">
    <DockPanel>
        <Menu Name="Menu" DockPanel.Dock="Top">
            <MenuItem Name="File" Header="_File">
                <MenuItem Name="Exit" Header="_Exit" />
            </MenuItem>
            <MenuItem Name="Save" Header="_Save">
                <MenuItem Name="Code" Header="_Code" />
                <MenuItem Name="EncryptedText" Header="_EncryptedText" />
            </MenuItem>
        </Menu>
        <Grid Background="#FFBDE2EA">
            <TextBox Name="Text_TextBox" HorizontalAlignment="Stretch" Height="22" Margin="133,170,125,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="640"/>
            <TextBox Name="Key_TextBox" HorizontalAlignment="Stretch" Height="22" Margin="133,95,125,0" TextWrapping="NoWrap" VerticalAlignment="Top" Width="640" HorizontalScrollBarVisibility="Hidden"/>
            <TextBox Name="IV_TextBox" HorizontalAlignment="Stretch" Height="22" Margin="133,135,125,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="640"/>
            <Label Name="Text_Label" Content="Text" HorizontalAlignment="Stretch" Margin="25,167,772,0" VerticalAlignment="Top" Width="101" FontWeight="Bold" Height="26"/>
            <Label Name="Key_Label" Content="Key" HorizontalAlignment="Stretch" Margin="25,94,772,0" VerticalAlignment="Top" Width="101" FontWeight="Bold" Height="26"/>
            <Label Name="IV_Label" Content="IV" HorizontalAlignment="Stretch" Margin="25,133,772,0" VerticalAlignment="Top" Width="101" FontWeight="Bold" Height="26"/>
            <Label Name="Code_Label" Content="Powershell Code:" HorizontalAlignment="Stretch" Margin="25,240,764,0" VerticalAlignment="Top" Width="109" FontWeight="Bold" Height="26"/>
            <Button Name="NewKey_Button" Content="New Key" HorizontalAlignment="Stretch" Margin="735,96,0,0" VerticalAlignment="Top" Width="74" Height="20" FontWeight="Bold"/>
            <Label Name="Config_Label" Content="Encrypted Text output file:" HorizontalAlignment="Stretch" Margin="25,20,701,0" VerticalAlignment="Top" Width="172" FontWeight="Bold" Height="26"/>
            <Border Name="ConfigPath_Border" BorderBrush="Black" BorderThickness="1" HorizontalAlignment="Stretch" Height="26" Margin="20,20,0,0" VerticalAlignment="Top" Width="458" ScrollViewer.HorizontalScrollBarVisibility="Hidden" >
                <TextBox Name="EncryptedTextPath_TextBox" HorizontalScrollBarVisibility="Hidden" TextWrapping="NoWrap" IsReadOnly="True"/>
            </Border>
            <TextBox Name="Script_TextBox" HorizontalAlignment="Stretch" Margin="10,266,0,0" TextWrapping="NoWrap" VerticalAlignment="Top" Height="249" Background="White" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto" IsReadOnly="True" Width="860" FontFamily="Lucida Console"/>
            <Button Name="CopyClipboard_Button" Content="Copy to Clipboard" HorizontalAlignment="Stretch" Margin="768,520,0,0" VerticalAlignment="Top" Width="107"/>
            <Button Name="Encrypt_Button" Content="Encrypt" HorizontalAlignment="Stretch" Margin="765,170,29,0" VerticalAlignment="Top" Width="75"/>
            <TextBox Name="EncryptedText_TextBox" HorizontalAlignment="Stretch" Height="22" Margin="133,207,125,0" TextWrapping="NoWrap" VerticalAlignment="Top" Width="640" HorizontalScrollBarVisibility="Hidden"/>
            <Label Name="EncryptedText_Label" Content="Encrypted Text" HorizontalAlignment="Stretch" Margin="25,204,772,0" VerticalAlignment="Top" Width="101" FontWeight="Bold" Height="26"/>
            <Button Name="CopyClipboard_Button2" Content="Copy to Clipboard" HorizontalAlignment="Stretch" Margin="768,208,0,0" VerticalAlignment="Top" Width="107"/>
        </Grid>
    </DockPanel>
</Window>

"@

# Read XAML Code
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
try{
     $Form = [Windows.Markup.XamlReader]::Load($reader)
     }
catch{
       Write-Host -Object "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered."
       #exit
       }

# Store Form Objects In PowerShell (Dynamic Variable Assignments based on 'Name=""' XAML Code)
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)}

$HereString1 = @'
############
# REQUIRED #
############
# Set TempDirectory Variable value to current folder from where this script is executed
if ($host.name -eq "ConsoleHost"){$TempDirectory = $MyInvocation.MyCommand.Path | split-path -Parent}

# Removes script from local filesystem after it is loaded into memory. (Prevent exposure of potential sensitive information)
$CurrentScriptFullPathName = $MyInvocation.MyCommand.Definition
$CurrentScriptName = $MyInvocation.MyCommand.Name
Remove-Item -Path $CurrentScriptFullPathName

#Helper Functions
function DecryptBytes {
                param ($SymetricAlgorithm,
                        $inputBytes
                        )
                $Transform = $SymetricAlgorithm.CreateDecryptor();
                $outputBlock = $Transform.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)
                return [System.Text.UnicodeEncoding]::Unicode.GetString($outputBlock)
                        }
function Get-SHA1{
    param ([String[]]$File)
    
    $StringBuilder = New-Object System.Text.StringBuilder
    $InputStream = New-Object System.IO.FileStream($File,[System.IO.FileMode]::Open)
    $Provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $Provider.ComputeHash($InputStream) | Foreach-Object { [void]$StringBuilder.Append($_.ToString("X2")) }
    $InputStream.Close()
    return ($StringBuilder.ToString())
}

#Try each type of AES, one is FIPS, other is not, at least one will work. (Depends on the .Net version or If DoD Lockdowns exist)
Try {$AESCryptoServiceProvider = New-Object System.Security.Cryptography.AesCryptoServiceProvider}
Catch {$AESCryptoServiceProvider = New-Object System.Security.Cryptography.RijndaelManaged}

$AESCryptoServiceProvider.Key = @(SCRIPTBOXKEY)
$AESCryptoServiceProvider.IV = @(SCRIPTBOXIV)

#Hash of saved text file
$OriginalHash = '<ORIGINALFILEHASH>'
#Import of secured password from encrypted text file
$CurrentHash = (Get-Sha1 -File "$TempDirectory\Pass.txt")
If($OriginalHash -ne $CurrentHash){Throw "Hash of ""$TempDirectory\Pass.txt"" does not match the original hash."; Exit 1}
#TempDirectory = Folder from where this script is execured i.E. #CABPATH\Scripts
$SecurePassword = [System.Convert]::FromBase64String((Get-Content -Path "$TempDirectory\Pass.txt"))
#remove txt file from local filesystem after loading into memory if hash matches and import was sucessfull.
If (($OriginalHash -eq $CurrentHash) -and !([String]::IsNullOrEmpty($SecurePassword))){Remove-Item -Path "$TempDirectory\Pass.txt"}


# Decrypted Password in Clear Text string. (Decrypt function + AES + SecurePassword)
$DecryptedPassword = DecryptBytes $AESCryptoServiceProvider $SecurePassword

######################################
#        Optional Examples           #
# Replace code below with your code: #
######################################

# Create PowerShell Credentials. Can be used to impersonate, runas, or authenticate with powershell functions.
$Credentials = New-Object System.Management.Automation.PSCredential("$UserName", (ConvertTo-SecureString -AsPlainText -Force -String (DecryptBytes $AESCryptoServiceProvider $SecurePassword)))
Start-Process cmd.exe -Credential $Credentials # Starts cmd.exe window using username and password specifiec in $Credentials
Start-Process iexplore.exe -ArgumentList "www.google.com" -Credential $Credentials

# Use with cmd.exe based win32 applications
& net user $UserName (DecryptBytes $AESCryptoServiceProvider $SecurePassword) /add /Comment:"Admin Account"
& net user $UserName ($Credentials.GetNetworkCredential().Password) /add /Comment:"Admin Account"


#Change (local) SQL Server Service Account Example
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | out-null
$SMOWmiserver = New-Object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer') $env:COMPUTERNAME
$ChangeService = $SMOWmiserver.Services | where {$_.name -eq "MSSQLSERVER"} # replace "MSSQLSERVER" with another instance name if needed.
$ChangeService.SetServiceAccount($UserName, (DecryptBytes $AESCryptoServiceProvider $SecurePassword))


# Use as argument in executable
$Exe = 'C:\Program Files\Test\test.exe'
$ExeFullName = (Get-ItemProperty -Path $Exe).FullName
$ExeSuccessCodes = @('0')
$ExeArguments = @('-U "John.Smith"', ('-p '+'"'+$DecryptedPassWord+'"'), '-T', '-A','-l "C:\Temp\Log.txt"')
$ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = $ExeFullName
$ProcessInfo.Arguments = $ExeArguments
$ProcessInfo.CreateNoWindow = $false
$ProcessInfo.UseShellExecute = $false
$ProcessInfo.RedirectStandardOutput = $false
$ProcessInfo.RedirectStandardError = $false
$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo
$Process.Start() | Out-Null
$Process.WaitforExit()
If (
     ($ExeSuccessCodes -contains $Process.ExitCode)
    ){
        Write-Verbose "Executed ""$($Process.StartInfo.FileName | Split-Path -Leaf)"". Exit code: $($Process.ExitCode)" -Verbose
      }
else{
     Write-Verbose """$($Process.StartInfo.FileName | Split-Path -Leaf)"" exited with a non-success exit code: $($Process.ExitCode)" -Verbose
     Exit $Process.ExitCode
     }
'@

#region Add events to Form Objects

$NewKey_Button.add_click({
                            If (![string]::IsNullOrEmpty(($Text_TextBox.Text))){$EncryptedText_TextBox.Text = $null}
                            If (![string]::IsNullOrEmpty($Script:ScriptBoxKey)){$Script:ScriptBoxKey = $null}
                            If (![string]::IsNullOrEmpty($Script:ScriptBoxIV)){$Script:ScriptBoxIV = $null}
                            $EncryptedTextPath_TextBox.Text = ""
                            $EncryptedText_TextBox.Text = ""
                            $EncryptedTextPath_TextBox = $null
                            $AESCryptoServiceProvider = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                            $AESCryptoServiceProvider.GenerateKey()
                            $AESCryptoServiceProvider.GenerateIV()
                            $Key_TextBox.Text       = $AESCryptoServiceProvider.Key
                            $IV_TextBox.Text        = $AESCryptoServiceProvider.IV
                            $ScriptKeyString        = $AESCryptoServiceProvider.Key
                            $Script:ScriptBoxKey    = "$ScriptKeyString" -replace ' ',','
                            $ScriptIVString         = $AESCryptoServiceProvider.IV
                            $Script:ScriptBoxIV     = "$ScriptIVString" -replace ' ',','
                            $Script_TextBox.Text    = $HereString1 -replace 'SCRIPTBOXKEY',"$ScriptBoxKey" -replace 'SCRIPTBOXIV',"$ScriptBoxIV"
                          })

$CopyClipboard_Button.add_click({
                                 #$Script_TextBox.Text.ToString().Trim() | clip.exe
                                 #if (![String]::IsNullOrEmpty($Script_TextBox.Text)){[System.Windows.Forms.Clipboard]::SetText($Script_TextBox.Text.ToString())}
                                 
                                 #This function copies the text to clipboard "as-is" and does not append new line. As well as works with MTA,STA and WPF.
                                 Set-Clipboard -InputObject ($Script_TextBox.Text.ToString())
                                 })

$CopyClipboard_Button2.add_click({
                                 #$EncryptedText_TextBox.Text.ToString().Trim() | clip.exe
                                 #if (![String]::IsNullOrEmpty($EncryptedText_TextBox.Text)){[System.Windows.Forms.Clipboard]::SetText($EncryptedText_TextBox.Text.ToString())}
                                 
                                 #This function copies the text to clipboard "as-is" and does not append new line. As well as works with MTA,STA and WPF.
                                 Set-Clipboard -InputObject ($EncryptedText_TextBox.Text.ToString())
                                 })

$Encrypt_Button.add_click({
                           
                           If (
                                ![string]::IsNullOrEmpty(($Text_TextBox.Text)) -and
                                ![string]::IsNullOrEmpty($Script:ScriptBoxKey) -and
                                ![string]::IsNullOrEmpty($Script:ScriptBoxIV)
                               ){
                                  If (![string]::IsNullOrEmpty(($Text_TextBox.Text))){$EncryptedText_TextBox.Text = $null}
                                  $AESCryptoServiceProvider     = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                                  $AESCryptoServiceProvider.Key = @($Script:ScriptBoxKey -split ",")
                                  $AESCryptoServiceProvider.IV  = @($Script:ScriptBoxIV  -Split ",")
                                  $EncryptedPassword            = EncryptString $AESCryptoServiceProvider ($Text_TextBox.Text)
                                  $EncryptedText_TextBox.text   = [System.Convert]::ToBase64String($EncryptedPassword) 
                                 }
                           
                           })

$Text_TextBox.Add_TextChanged({$EncryptedText_TextBox.Text = $null})                        
#Menu Buttons
$Exit.add_click({
                 $Form.Close()
                 Exit
                 })

$Code.add_click({
                 $SaveFilePath = Set-FileName -initialDirectory $env:USERPROFILE
                 If (
                      ![string]::IsNullOrEmpty(($SaveFilePath))
                     ){
                       If (
                           !(Test-Path -Path $SaveFilePath)
                           ){
                              [system.io.file]::WriteAllText("$SaveFilePath", $Script_TextBox.text)
                             }
                       else{
                             Remove-Item -Path $SaveFilePath -Force
                             [system.io.file]::WriteAllText("$SaveFilePath", $Script_TextBox.text)
                            }
                       }
                 })

$EncryptedText.add_click({
                            If (
                                ![string]::IsNullOrEmpty(($EncryptedText_TextBox.Text))
                                ){
                                    $SaveFilePath = Set-FileName2 -initialDirectory $env:USERPROFILE
                                    If (
                                        ![string]::IsNullOrEmpty(($SaveFilePath))
                                        ){                                  
                                           If (
                                                !(Test-Path -Path $SaveFilePath)
                                              ){
                                                 #$EncryptedText_TextBox.text | Add-Content -Path $SaveFilePath
                                                 #$EncryptedText_TextBox.Text >> $SaveFilePath
                                                 [system.io.file]::WriteAllText("$SaveFilePath", $EncryptedText_TextBox.Text)
                                                 $EncryptedTextPath_TextBox.Text = $SaveFilePath
                                                 $TextPath = ($EncryptedTextPath_TextBox.Text | Split-Path -Leaf)
                                                 $Hash = (Get-SHA1 -File ($EncryptedTextPath_TextBox.Text))
                                                 $Script_TextBox.Text = ($HereString1 -replace 'SCRIPTBOXKEY',"$ScriptBoxKey" -replace 'SCRIPTBOXIV',"$ScriptBoxIV" -replace 'PASS.txt',"$TextPath" -replace '<ORIGINALFILEHASH>', "$Hash")
                                                }
                                           else{
                                                 Remove-Item -Path $SaveFilePath -Force
                                                 #$EncryptedText_TextBox.Text | Add-Content -Path $SaveFilePath
                                                 [system.io.file]::WriteAllText("$SaveFilePath", $EncryptedText_TextBox.Text)
                                                 $EncryptedTextPath_TextBox.Text = $SaveFilePath
                                                 $TextPath = ($SaveFilePath | Split-Path -Leaf)
                                                 $Hash = (Get-SHA1 -File $SaveFilePath)
                                                 $Script_TextBox.Text = ($HereString1 -replace 'SCRIPTBOXKEY',"$ScriptBoxKey" -replace 'SCRIPTBOXIV',"$ScriptBoxIV" -replace 'PASS.txt',"$TextPath" -replace '<ORIGINALFILEHASH>', "$Hash")
                                                }
                                          }
                                  }
                            
                          })

#endregion Add events to Form Object

#region Show the form
#$Form.Icon = "path to .ico"
$Form.WindowStartupLocation = 'CenterScreen'
#$Form.Topmost = $true
$Form.ShowDialog() | out-null
#endregion Show the form