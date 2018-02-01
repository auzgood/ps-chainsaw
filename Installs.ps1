#region Functions

if ( ![string]::IsNullOrEmpty($TempDirectory) ) {
    Write-Log "   INFO: The TempDirectory parameter has been set to ""$TempDirectory""."
}

Function New-SafeRegKey {
    Param([String]$Path)
    Begin{
        $RegArray = @()
        foreach ($Item in ($Path -split '\\')){$RegArray += $Item}
        [String]$ResolvedPath = $null
        $Count = 1
    }
    Process{
        while ($Count -lt $RegArray.Count) {
            if( [String]::IsNullOrEmpty($ResolvedPath) -and (Test-Path ($RegArray[($Count - 1)])) ) {
                [String]$ResolvedPath = ($RegArray[($Count - 1)])
            }
            elseIf ( ![String]::IsNullOrEmpty($ResolvedPath) ) {
                [String]$ResolvedPath += ("\"+($RegArray[($Count - 1)]))
                    if ( (Test-Path $ResolvedPath) -and !(Test-Path ("$ResolvedPath\"+$RegArray[($Count)])) ) {
                        New-Item -Path $ResolvedPath -Name $RegArray[($Count)] | Out-Null
                    }
                    else {}
            }
            $Count++
        }
    }
    end {
        return (Get-Item -Path $Path)
    }
}

Function Check-Installation {
    Param (
            [Parameter(Mandatory=$true,
                        ValueFromPipelineByPropertyName=$true,
                        Position=0)]
            [ValidateNotNullOrEmpty()]
            [string]$Patch
            )
    if ( ($Update1 -contains $Patch) -or ($HOTFIXIDLIST -contains $Patch)-or ($KBList -contains $Patch) -or ($Updates -contains $Patch) ) {
        $true
    }
    else {
        $false
    }
}

#endregion

#region $TempDirectory Assignment
if ($host.name -eq 'ConsoleHost') {
    if ( [string]::IsNullOrEmpty($TempDirectory) ) {
        $TempDirectory = $MyInvocation.MyCommand.Path | split-path -Parent
    }
}
else {
    if ( [string]::IsNullOrEmpty($TempDirectory) -and ($host.name -match 'ISE') ) {
        #region Open Folder Dialog to select $TempDirectory Parameter if not specified.
        Function Select-FolderDialog {
            param([string]$Description="Select Folder",[string]$RootFolder="Desktop")
            [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null     
            $objForm = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
            $objForm.Rootfolder = $RootFolder
            $objForm.Description = $Description
            $Show = $objForm.ShowDialog()
                if ($Show -eq "OK") {
                    Return $objForm.SelectedPath
                } else {
                    Write-Error -Message "Operation cancelled by user."
                }
        }
        $TempDirectory = Select-FolderDialog
        #endregion Open Folder Dialog to select $TempDirectory Parameter if not specified.
    }
}
#endregion $TempDirectory Assignment

#region Logging
$Logfile = ("C:\" + '\' + ("script.txt"))

Function Write-Log {

Param ([string]$logstring)
$DateTime = Get-Date -Format "yyy-MM-dd HH:mm:ss"
Add-Content $Logfile -value "$DateTime $logstring"
}
#endregion Logging

#region MS PATCH: VARIABLES

$MSPatchRegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D0C7E3F1-4A13-479C-9B7A-E623182CA901}\MS Patches"

#$Silent     = $true #$true sets to /quiet or /SILENT, $false sets it to /PASSIVE (still unattended, but progress shows)
$OS = (Get-WmiObject -Class Win32_OperatingSystem).caption
if ($OS -match "Microsoft Windows Embedded Standard") {
    $MSPatchFolder      = $TempDirectory + "\MSPatches\WES7"
    $MSPatchTitleCSV    = $TempDirectory + "\MSPatches\WES7\20150604-HotFixTitles.csv"
}
else {
    $MSPatchFolder      = $TempDirectory + "\MSPatches\WIN10"
    $MSPatchTitleCSV    = $TempDirectory + "\MSPatches\WIN10\20150604-HotFixTitles.csv"
}

#endregion MS PATCH: VARIABLES

#region MSU Installations

IF (
     !!(Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Extension -match '.msu'})
    ){
       
       Write-Log "   INFO: Found "".MSU"" patches to be installed."
       #region Import MSPatchTitleCSV if exists
       If (
            ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
            (Test-Path -Path $MSPatchTitleCSV)
           ){
              $HotFixTitleFile = $MSPatchTitleCSV | Split-Path -Leaf
              Write-Log ("   INFO: Found " + "'"+ ($MSPatchTitleCSV | Split-Path -leaf)+"'"+ " containing KB Title information. Using this file to reference title information during installation of Hotfixes.")
              $PKBCsv = Import-Csv -Path $MSPatchTitleCSV -ErrorAction SilentlyContinue
             }
       Elseif (
               [String]::IsNullOrEmpty($MSPatchTitleCSV) -or
               !(Test-Path -Path $MSPatchTitleCSV)
               ){
                 If (
                      [String]::IsNullOrEmpty($MSPatchTitleCSV)
                     ){
                        Write-Log "   INFO: No CSV file containing hotfix title information found. Proceeding with installation(s) without title information."
                       }
                 Elseif (
                         ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
                         !(Test-Path -Path $MSPatchTitleCSV)
                         ){
                           Write-Log '   INFO: "$MSPatchTitleCSV" specified in variables section has not been detected.on found. Proceeding with installation(s) without title information.'
                           }
                 }
       #endregion Import MSPatchTitleCSV if exists
       Write-Log "   INFO: Proceeding with MSU patches..."
       Foreach (
                 $MSU in (Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Name -match '.MSU'})
                ){
                  $PatchNumber++
                  $PKB = (($MSU.Name).Split('-') | Select-String -Pattern "KB")
                  If (
                         !!(Check-Installation -Patch $PKB)
                        ){
                            Write-Log "   INFO: Previously Installed ""$MSU"". Skipping Patch $PatchNumber of $PatchCountTotal"
                            If ($MSPatchRegistryKey){
                                                        If (
                                                            !(Test-Path -Path $MSPatchRegistryKey)
                                                        ){
                                                            New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        else {
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        If (
                                                            (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                            ){
                                                            Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                            }
                                                    }
                            Remove-Item -Path ($MSU.FullName) -Force
                          }
                  Else {
                          #region Patch Description (KB Title) check
                          If ( #if CSV exists.. 
                               !!$PKBCsv
                              ){
                                 # assign $PKB to the KB number from filename
                                 $PKB = (($MSU.Name).Split('-') | Select-String -Pattern "KB")
                                 If ( #csv Exists and contains a value for Title for the patch.
                                      !!$PKBCsv -and
                                      ![String]::IsNullOrEmpty($PKB) -and
                                      ![String]::IsNullOrEmpty(($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title)
                                     ){
                                        $PKBTitle = ($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title
                                        Write-Host -Object ""
                                        Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. ""$MSU"" Addresses: ""$PKBTitle""."
                                       }
                                 else {
                                        Write-Host -Object ""
                                        Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. $MSU"
                                       }
                                }
                          else {
                                 Write-Host -Object ""
                                 Write-Host -Object ""
                                 Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. $MSU"
                                 }
                          #endregion Patch Description (KB Title) check

                          #region Patch Execution
                          $MSUFullName= (Get-ItemProperty -Path $MSPatchFolder\$MSU).FullName
                          $MSUSuccessCodes = @("0","1639","3010","2359302","-2145124329")
                          $MSUArguments = @("""$MSUFullName"" " , "/quiet " , "/norestart")
                          $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo "wusa.exe"
                          $ProcessInfo.arguments = $MSUArguments
                          $ProcessInfo.CreateNoWindow = $false
                          $ProcessInfo.UseShellExecute = $false
                          $ProcessInfo.RedirectStandardOutput = $false
                          $ProcessInfo.RedirectStandardError = $false
                          $Process = New-Object System.Diagnostics.Process
                          $Process.StartInfo = $processInfo
                          $Process.Start() | Out-Null
                          $Process.WaitforExit()
                          #endregion Patch Execution

                          #region MSU Install Status Checks
                          If (
                               $MSUSuccessCodes -contains $Process.ExitCode
                              ){
                                If ($Process.ExitCode -eq -2145124329){
                                                                       Write-Log "   INFO: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Is NOT APPLICABLE."
                                                                       Remove-Item -Path ($MSU.FullName) -Force
                                                                       }
                                If ($Process.ExitCode -eq 2359302){
                                                                    Write-Log "   INFO: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Is already installed."
                                                                    If ($MSPatchRegistryKey){
                                                                                              If (
                                                                                                    !(Test-Path -Path $MSPatchRegistryKey)
                                                                                                   ){
                                                                                                      New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                                      New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                                     }
                                                                                              else {
                                                                                                     New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                                    }
                                                                                              If (
                                                                                                   (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                                  ){
                                                                                                     Write-Log "SUCCESS: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                                    }
                                                                                             }
                                                                    Remove-Item -Path ($MSU.FullName) -Force
                                                                   }
                                If ($Process.ExitCode -eq 3010){
                                                                Write-Log "SUCCESS: Installer ""$MSU"" installed, but will require a reboot for completion."
                                                                If ($MSPatchRegistryKey){
                                                                                         If (
                                                                                             !(Test-Path -Path $MSPatchRegistryKey)
                                                                                            ){
                                                                                               New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                              }
                                                                                         else {
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                               }
                                                                                         If (
                                                                                              (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                             ){
                                                                                                Write-Log "SUCCESS: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                               }
                                                                                        }
                                                                Remove-Item -Path ($MSU.FullName) -Force
                                                                }
                                If ($Process.ExitCode -eq 0){
                                                              Write-Log "SUCCESS: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Installed Successfully."
                                                              If ($MSPatchRegistryKey){
                                                                                         If (
                                                                                             !(Test-Path -Path $MSPatchRegistryKey)
                                                                                            ){
                                                                                               New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                              }
                                                                                         else {
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                               }
                                                                                         If (
                                                                                              (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                             ){
                                                                                                Write-Log "SUCCESS: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                               }
                                                                                        }
                                                              Remove-Item -Path ($MSU.FullName) -Force
                                                             }
                                }
                          else {
                                 Write-Log ("FAILURE: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Failed with ExitCode:" + $Process.ExitCode)
                                 Exit $Process.ExitCode
                                }
                          #endregion MSU Install Status Checks
                        }
                 }
      }

#endregion MSU installations

#region System environment variables.
$DotNetVersion = (Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} | select -ExpandProperty Version | Sort-Object -Descending | select -First 1)
$PatchCountTotal = (Get-ChildItem -Path $MSPatchFolder -Recurse | Where-Object {($_.Extension -ne '.zip') -and ($_.Extension -ne '.csv') -and ($_.Extension -ne '.xml') -and ($_.Mode -notmatch 'd')}).count
$PatchNumber = 0
#endregion

#region Import MSPatchTitleCSV if exists
        If (
             ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
             (Test-Path -Path $MSPatchTitleCSV)
            ){
               $HotFixTitleFile = $MSPatchTitleCSV | Split-Path -Leaf
               Write-Log "   INFO: Found " + "'"+ ($MSPatchTitleCSV | Split-Path -leaf)+"'"+ " containing KB Title information. Using this file to reference title information during installation of Hotfixes."
               $PKBCsv = Import-Csv -Path $MSPatchTitleCSV -ErrorAction SilentlyContinue
              }
        Elseif (
                [String]::IsNullOrEmpty($MSPatchTitleCSV) -or
                !(Test-Path -Path $MSPatchTitleCSV)
                ){
                  If (
                       [String]::IsNullOrEmpty($MSPatchTitleCSV)
                      ){
                         Write-Log "   INFO: No CSV file containing hotfix title information found. Proceeding with installation(s) without title information."
                        }
                  Elseif (
                          ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
                          !(Test-Path -Path $MSPatchTitleCSV)
                          ){
                            Write-Log '   INFO: "$MSPatchTitleCSV" specified in variables section has not been detected.on found. Proceeding with installation(s) without title information.'
                            }
                  }
#endregion Import MSPatchTitleCSV if exists

#region Starting WUAUSERV service
Write-Host -Object "" #for spacing
IF (
     !((Get-WmiObject -Class win32_Service | Where-Object {$_.Name -match 'wuauserv'}).StartMode -match "Auto")
    ){
      Write-Log "   INFO: Setting the Windows Update Service (WUAUSERV) to StartMode of 'Auto'"
      Set-Service -Name wuauserv -StartupType Automatic 
      Start-Sleep -Milliseconds 100
      If (
           (Get-WmiObject -Class win32_Service | Where-Object {$_.Name -match 'wuauserv'}).StartMode -match "Auto"
          ){
             Write-Log "SUCCESS: Set the Windows Update Service (WUAUSERV) to StartMode of 'Auto'"
            }
      }
IF (
     !((Get-Service -Name wuauserv).Status -match "running")
    ){
      Write-Log "   INFO: Starting the Windows Update Service (WUAUSERV)"
      Start-Service -Name wuauserv
      
      #wait for service to start
      While(
             (Get-Service -Name wuauserv).Status -ne 'Running'
            ){
              Start-Sleep -Seconds 5
              Write-Log "   INFO: Waiting  for Windows Update Service (WUAUSERV) to start."
              }
      If (
           (Get-Service -Name wuauserv).Status -eq 'Running'
          ){
             Write-Log "SUCCESS: Windows Update Service (WUAUSERV) has started. Proceeding with patch installation(s)."
            }
      }
else {
      Write-Log "   INFO: Windows Update Service (WUAUSERV) is already running. Proceeding with patch installation(s)."
      }



#endregion

#region Disable CRL for DotNet Installers
Write-Log "   INFO: Setting User Registry keys to allow Dot Net Install."
$CRLReg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing'
$CRLKey = 'State'
$NewCRLValue = '146432'
If (
     (Get-ItemProperty -Path $CRLReg).State -notmatch $NewCRLValue
    ) {
        Write-Log "   INFO: Required registry value to allow offline DotNet Framework Install is not set."
        $OldCrlValue = (Get-ItemProperty -Path $CRLReg).State
        Write-Log "   INFO: Saved the old registry key ""$CRLKey"" value of ""$OldCrlValue"" to Variable."
        Write-Host -Object ""
        Write-Log "   INFO: Applying Registry setting to allow offline DotNet installers to run."
        Set-ItemProperty -Path $CRLReg -Name $CRLKey -Value $NewCRLValue | Out-Null
        If (
             (Get-ItemProperty -Path $CRLReg).State -match $NewCRLValue
            ){
               Write-Log "SUCCESS: The change for registry property named $CRLKey applied successfully. Proceeding with Installation(s)."
              }
       }
elseif (
        (Get-ItemProperty -Path $CRLReg).State -match $NewCRLValue
        ){
          Write-Log "   INFO: The Registry setting to allow offline DotNet installers to run is already present. Proceeding with Installation(s)"
          }
elseif (
        Write-Log "FAILURE: Could not update registry setting to allow offline DotNet installers to run."
        ){
          }
#endregion

#region .NET 4.0 Patches
If (
    ($DotNetVersion -match '4.0')
    ) {
        #region Import MSPatchTitleCSV if exists
        If (
             ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
             (Test-Path -Path $MSPatchTitleCSV)
            ){
               $HotFixTitleFile = $MSPatchTitleCSV | Split-Path -Leaf
               Write-Log "   INFO: Found " + "'"+ ($MSPatchTitleCSV | Split-Path -leaf)+"'"+ " containing KB Title information. Using this file to reference title information during installation of Hotfixes."
               $PKBCsv = Import-Csv -Path $MSPatchTitleCSV -ErrorAction SilentlyContinue
              }
        Elseif (
                [String]::IsNullOrEmpty($MSPatchTitleCSV) -or
                !(Test-Path -Path $MSPatchTitleCSV)
                ){
                  If (
                       [String]::IsNullOrEmpty($MSPatchTitleCSV)
                      ){
                         Write-Log "   INFO: No CSV file containing hotfix title information found. Proceeding with installation(s) without title information."
                        }
                  Elseif (
                          ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
                          !(Test-Path -Path $MSPatchTitleCSV)
                          ){
                            Write-Log '   INFO: "$MSPatchTitleCSV" specified in variables section has not been detected.on found. Proceeding with installation(s) without title information.'
                            }
                  }
       #endregion Import MSPatchTitleCSV if exists
        If ($Silent){$SilentArgument = "/Q "}
        else {$SilentArgument = "/PASSIVE "}
        Write-Log "   INFO: .NET 4.0 Installed... Installing .NET 4.0 Patches..."
        Foreach (
                 $DotNet40Patch in (Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Name -match 'NDP40'})
                 ) {
                    $PatchNumber++
                    $PKB = (($DotNet40Patch.Name).Split('-') | Select-String -Pattern "KB")

                    If (
                         !!(Check-Installation -Patch $PKB)
                        ){
                            Write-Log "   INFO: Previously Installed ""$DotNet40Patch"". Skipping Patch $PatchNumber of $PatchCountTotal"
                            If ($MSPatchRegistryKey){
                                                        If (
                                                            !(Test-Path -Path $MSPatchRegistryKey)
                                                        ){
                                                            New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        else {
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        If (
                                                            (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                            ){
                                                              Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                            }
                                                    }
                            Remove-Item -Path ($DotNet40Patch.FullName) -Force
                          }
                    Else {
                            #region Patch Description (KB Title) check
                            If ( #if CSV exists.. 
                                    !!$PKBCsv
                                ){
                                    # assign $PKB to the KB number from filename
                                    $PKB = (($DotNet40Patch.Name).Split('-') | Select-String -Pattern "KB")
                                    }
                            If ( #csv Exists and contains a value for Title for the patch.
                                    !!$PKBCsv -and
                                    ![String]::IsNullOrEmpty(($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title)
                                ){
                                    $PKBTitle = ($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title
                                    Write-Host -Object ""
                                    Write-Host -Object ""
                                    Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. ""$DotNet40Patch"" Resolves: ""$PKBTitle""."
                                    }
                            else {
                                    Write-Host -Object ""
                                    Write-Host -Object ""
                                    Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. $DotNet40Patch"
                                    }
                            #endregion Patch Description (KB Title) check

                            #region Patch Execution
                            $DN40FullName = (Get-ItemProperty -Path $MSPatchFolder\$DotNet40Patch).FullName
                            $DN40SuccessCodes = @("0","1639","3010")
                            $DN40Arguments = @($SilentArgument , "/NORESTART")
                            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                            $ProcessInfo.FileName = $DN40FullName
                            $ProcessInfo.arguments = $DN40Arguments
                            $ProcessInfo.CreateNoWindow = $false
                            $ProcessInfo.UseShellExecute = $false
                            $ProcessInfo.RedirectStandardOutput = $false
                            $ProcessInfo.RedirectStandardError = $false
                            $Process = New-Object System.Diagnostics.Process
                            $Process.StartInfo = $ProcessInfo
                            $Process.Start() | Out-Null
                            $Process.WaitforExit()
                            #endregion Patch Exectuion

                            #region Patch validation
                            If (
                                $DN40SuccessCodes -contains $Process.ExitCode
                                ){
                                   Write-Log "SUCCESS: Completed $DotNet40Patch Install."
                                   If ($MSPatchRegistryKey){
                                                             If (
                                                                 !(Test-Path -Path $MSPatchRegistryKey)
                                                                ){
                                                                   New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                                   New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                                  }
                                                             else {
                                                                   New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                                   }
                                                             If (
                                                                  (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                 ){
                                                                    Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                   }
                                                            }
                                   Remove-Item -Path ($DotNet40Patch.FullName) -Force
                                  }
                            elseif (
                                    !($DN40SuccessCodes -contains $Process.ExitCode)
                                    ){
                                       Write-Log ("FAILURE: Unable to install $DotNet40Patch successfully. Exit Code: " + $Process.ExitCode)
                                       Exit $Process.ExitCode
                                      }
                            #endregion Patch validation
                          }
                    }
       }
else {
      foreach (
               $DotNet40Patch in (Get-ChildItem -Path $MSPatchFolder | Where-Object {$_.Name -match 'NDP40'})
               ){
                  $PatchNumber++
                  Write-Log "   INFO: NOT APPLICABLE: ""$DotNet40Patch"". Skipping Patch $PatchNumber of $PatchCountTotal"
                  Remove-Item -Path ($DotNet40Patch.FullName) -Force
                 }
      
      }
#endregion .NET 4.0 Updates

#region .NET 4.6 Patches
If (
    ($DotNetVersion -match '4.6')
    ) {
        
        #region Import MSPatchTitleCSV if exists
        If (
             ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
             (Test-Path -Path $MSPatchTitleCSV)
            ){
               $HotFixTitleFile = $MSPatchTitleCSV | Split-Path -Leaf
               Write-Log ("   INFO: Found " + "'"+ ($MSPatchTitleCSV | Split-Path -leaf)+"'"+ " containing KB Title information. Using this file to reference title information during installation of Hotfixes.")
               $PKBCsv = Import-Csv -Path $MSPatchTitleCSV -ErrorAction SilentlyContinue
              }
        Elseif (
                [String]::IsNullOrEmpty($MSPatchTitleCSV) -or
                !(Test-Path -Path $MSPatchTitleCSV)
                ){
                  If (
                       [String]::IsNullOrEmpty($MSPatchTitleCSV)
                      ){
                         Write-Log "   INFO: No CSV file containing hotfix title information found. Proceeding with installation(s) without title information."
                        }
                  Elseif (
                          ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
                          !(Test-Path -Path $MSPatchTitleCSV)
                          ){
                            Write-Log '   INFO: "$MSPatchTitleCSV" specified in variables section has not been detected.on found. Proceeding with installation(s) without title information.'
                            }
                  }
       #endregion Import MSPatchTitleCSV if exists
        
        If ($Silent){$SilentArgument = "/Q "}
        else {$SilentArgument = "/PASSIVE "}
        Write-Log "   INFO: .NET 4.5 Installed... Installing .NET 4.6 Patches..."
        Foreach (
                 $DotNet45Patch in (Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Name -match 'NDP46'})
                 ){
                    $PatchNumber++
                    $PKB = (($DotNet45Patch.Name).Split('-') | Select-String -Pattern "KB")

                    If (
                         !!(Check-Installation -Patch $PKB)
                        ){
                            Write-Log "   INFO: Previously Installed ""$DotNet45Patch"". Skipping Patch $PatchNumber of $PatchCountTotal"
                            If ($MSPatchRegistryKey){
                                                        If (
                                                            !(Test-Path -Path $MSPatchRegistryKey)
                                                        ){
                                                            New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        else {
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        If (
                                                            (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                            ){
                                                            Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                            }
                                                    }
                            Remove-Item -Path ($DotNet45Patch.FullName) -Force
                          }
                    Else {
                            #region Patch Description (KB Title) check
                            If ( #if CSV exists.. 
                                 !!$PKBCsv
                                ){
                                   # assign $PKB to the KB number from filename
                                   $PKB = (($DotNet45Patch.Name).Split('-') | Select-String -Pattern "KB")
                                  }
                            If ( #csv Exists and contains a value for Title for the patch.
                                 !!$PKBCsv -and
                                 ![String]::IsNullOrEmpty(($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title)
                                ){
                                   $PKBTitle = ($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title
                                   Write-Host -Object ""
                                   Write-Host -Object ""
                                   Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. ""$DotNet45Patch"" Addresses: ""$PKBTitle""."
                                  }
                            else {
                                   Write-Host -Object ""
                                   Write-Host -Object ""
                                   Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. $DotNet45Patch"
                                  }
                            #endregion Patch Description (KB Title) check                            

                            #region Patch Execution
                            $DN45FullName = (Get-ItemProperty -Path $MSPatchFolder\$DotNet45Patch).FullName
                            $DN45SuccessCodes = @("0","1639","3010")
                            $DN45Arguments = @($SilentArgument , "/NORESTART")
                            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                            $ProcessInfo.FileName = $DN45FullName
                            $ProcessInfo.arguments = $DN45Arguments
                            $ProcessInfo.CreateNoWindow = $false
                            $ProcessInfo.UseShellExecute = $false
                            $ProcessInfo.RedirectStandardOutput = $false
                            $ProcessInfo.RedirectStandardError = $false
                            $Process = New-Object System.Diagnostics.Process
                            $Process.StartInfo = $ProcessInfo
                            $Process.Start() | Out-Null
                            $Process.WaitforExit()
                            #endregion Patch Execution

                            #region Patch validation
                            If (
                                $DN45SuccessCodes -contains $Process.ExitCode
                                ){
                                   Write-Log "SUCCESS: Completed $DotNet45Patch Install."
                                   If ($MSPatchRegistryKey){
                                                             If (
                                                                 !(Test-Path -Path $MSPatchRegistryKey)
                                                                ){
                                                                   New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                                   New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                                  }
                                                             else {
                                                                   New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                                   }
                                                             If (
                                                                  (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                 ){
                                                                    Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                   }
                                                            }
                                   Remove-Item -Path ($DotNet45Patch.FullName) -Force
                                  }
                            ElseIf (
                                    ($Process.ExitCode -eq 1642)
                                    ){
                                      Write-Log "   INFO: $DotNet45Patch is not applicable."
                                      Remove-Item -Path ($DotNet45Patch.FullName) -Force
                                      }
                            Elseif (
                                    !($DN45SuccessCodes -contains $Process.ExitCode)
                                    ){
                                       Write-Log ("FAILURE: Unable to install $DotNet45Patch successfully. Exit Code: " + $Process.ExitCode)
                                       Exit $Process.ExitCode
                                      }

                            #endregion Patch validation
                          }
                    }
       }
else {
      foreach (
               $DotNet45Patch in (Get-ChildItem -Path $MSPatchFolder | Where-Object {$_.Name -match 'NDP46'})
               ){
                 $PatchNumber++
                 Write-Log "   INFO: NOT APPLICABLE: ""$DotNet45Patch"". Skipping Patch $PatchNumber of $PatchCountTotal"
                 Remove-Item -Path ($DotNet45Patch.FullName) -Force
                 }
      }

#endregion .NET 4.6 Updates

#region MSU Installations

IF (
     !!(Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Extension -match '.msu'})
    ){
       
       Write-Log "   INFO: Found "".MSU"" patches to be installed."
       #region Import MSPatchTitleCSV if exists
       If (
            ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
            (Test-Path -Path $MSPatchTitleCSV)
           ){
              $HotFixTitleFile = $MSPatchTitleCSV | Split-Path -Leaf
              Write-Log ("   INFO: Found " + "'"+ ($MSPatchTitleCSV | Split-Path -leaf)+"'"+ " containing KB Title information. Using this file to reference title information during installation of Hotfixes.")
              $PKBCsv = Import-Csv -Path $MSPatchTitleCSV -ErrorAction SilentlyContinue
             }
       Elseif (
               [String]::IsNullOrEmpty($MSPatchTitleCSV) -or
               !(Test-Path -Path $MSPatchTitleCSV)
               ){
                 If (
                      [String]::IsNullOrEmpty($MSPatchTitleCSV)
                     ){
                        Write-Log "   INFO: No CSV file containing hotfix title information found. Proceeding with installation(s) without title information."
                       }
                 Elseif (
                         ![String]::IsNullOrEmpty($MSPatchTitleCSV) -and
                         !(Test-Path -Path $MSPatchTitleCSV)
                         ){
                           Write-Log '   INFO: "$MSPatchTitleCSV" specified in variables section has not been detected.on found. Proceeding with installation(s) without title information.'
                           }
                 }
       #endregion Import MSPatchTitleCSV if exists
       Write-Log "   INFO: Proceeding with MSU patches..."
       Foreach (
                 $MSU in (Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Name -match '.MSU'})
                ){
                  $PatchNumber++
                  $PKB = (($MSU.Name).Split('-') | Select-String -Pattern "KB")
                  If (
                         !!(Check-Installation -Patch $PKB)
                        ){
                            Write-Log "   INFO: Previously Installed ""$MSU"". Skipping Patch $PatchNumber of $PatchCountTotal"
                            If ($MSPatchRegistryKey){
                                                        If (
                                                            !(Test-Path -Path $MSPatchRegistryKey)
                                                        ){
                                                            New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        else {
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                            }
                                                        If (
                                                            (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                            ){
                                                            Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                            }
                                                    }
                            Remove-Item -Path ($MSU.FullName) -Force
                          }
                  Else {
                          #region Patch Description (KB Title) check
                          If ( #if CSV exists.. 
                               !!$PKBCsv
                              ){
                                 # assign $PKB to the KB number from filename
                                 $PKB = (($MSU.Name).Split('-') | Select-String -Pattern "KB")
                                 If ( #csv Exists and contains a value for Title for the patch.
                                      !!$PKBCsv -and
                                      ![String]::IsNullOrEmpty($PKB) -and
                                      ![String]::IsNullOrEmpty(($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title)
                                     ){
                                        $PKBTitle = ($PKBCsv | Where-Object {$_.HotFixID -match "$PKB"}).Title
                                        Write-Host -Object ""
                                        Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. ""$MSU"" Addresses: ""$PKBTitle""."
                                       }
                                 else {
                                        Write-Host -Object ""
                                        Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. $MSU"
                                       }
                                }
                          else {
                                 Write-Host -Object ""
                                 Write-Host -Object ""
                                 Write-Log "   INFO: Installing Patch $PatchNumber of $PatchCountTotal. $MSU"
                                 }
                          #endregion Patch Description (KB Title) check

                          #region Patch Execution
                          $MSUFullName= (Get-ItemProperty -Path $MSPatchFolder\$MSU).FullName
                          $MSUSuccessCodes = @("0","1639","3010","2359302","-2145124329")
                          $MSUArguments = @("""$MSUFullName"" " , "/quiet " , "/norestart")
                          $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo "wusa.exe"
                          $ProcessInfo.arguments = $MSUArguments
                          $ProcessInfo.CreateNoWindow = $false
                          $ProcessInfo.UseShellExecute = $false
                          $ProcessInfo.RedirectStandardOutput = $false
                          $ProcessInfo.RedirectStandardError = $false
                          $Process = New-Object System.Diagnostics.Process
                          $Process.StartInfo = $processInfo
                          $Process.Start() | Out-Null
                          $Process.WaitforExit()
                          #endregion Patch Execution

                          #region MSU Install Status Checks
                          If (
                               $MSUSuccessCodes -contains $Process.ExitCode
                              ){
                                If ($Process.ExitCode -eq -2145124329){
                                                                       Write-Log "   INFO: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Is NOT APPLICABLE."
                                                                       Remove-Item -Path ($MSU.FullName) -Force
                                                                       }
                                If ($Process.ExitCode -eq 2359302){
                                                                    Write-Log "   INFO: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Is already installed."
                                                                    If ($MSPatchRegistryKey){
                                                                                              If (
                                                                                                    !(Test-Path -Path $MSPatchRegistryKey)
                                                                                                   ){
                                                                                                      New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                                      New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                                     }
                                                                                              else {
                                                                                                     New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                                    }
                                                                                              If (
                                                                                                   (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                                  ){
                                                                                                     Write-Log "SUCCESS: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                                    }
                                                                                             }
                                                                    Remove-Item -Path ($MSU.FullName) -Force
                                                                   }
                                If ($Process.ExitCode -eq 3010){
                                                                Write-Log "SUCCESS: Installer ""$MSU"" installed, but will require a reboot for completion."
                                                                If ($MSPatchRegistryKey){
                                                                                         If (
                                                                                             !(Test-Path -Path $MSPatchRegistryKey)
                                                                                            ){
                                                                                               New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                              }
                                                                                         else {
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                               }
                                                                                         If (
                                                                                              (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                             ){
                                                                                                Write-Log "SUCCESS: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                               }
                                                                                        }
                                                                Remove-Item -Path ($MSU.FullName) -Force
                                                                }
                                If ($Process.ExitCode -eq 0){
                                                              Write-Log "SUCCESS: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Installed Successfully."
                                                              If ($MSPatchRegistryKey){
                                                                                         If (
                                                                                             !(Test-Path -Path $MSPatchRegistryKey)
                                                                                            ){
                                                                                               New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                              }
                                                                                         else {
                                                                                               New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                               }
                                                                                         If (
                                                                                              (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                             ){
                                                                                                Write-Log "SUCCESS: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                               }
                                                                                        }
                                                              Remove-Item -Path ($MSU.FullName) -Force
                                                             }
                                }
                          else {
                                 Write-Log ("FAILURE: Installer ""$MSU"". Patch $PatchNumber of $PatchCountTotal. Failed with ExitCode:" + $Process.ExitCode)
                                 Exit $Process.ExitCode
                                }
                          #endregion MSU Install Status Checks
                        }
                 }
      }

#endregion MSU installations

#region MSI Installers

IF (
     !!(Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Extension -match '.msi'})
    ) {
        If ($Silent){$SilentArgument = " /QUIET"}
        else {$SilentArgument = " /PASSIVE"}
        Foreach (
                $MSI in (Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Extension -match '.msi'})
                 ){
                     $PatchNumber++
                     Write-Host -Object ""
                     Write-Log "   INFO: Installing ""$MSI"". Patch $PatchNumber of $PatchCountTotal"
                     #region Patch Execution
                     $MSISuccessCodes = @("0","1639","3010")
                     $MSILog = ($env:temp + ("\$MSI" -replace ".msi",".log" -replace ' ', '_'))
                     $MSIFullName = ($MSI.Fullname)
                     $MSIArguments = "/I " + """$MSIFullName""" + $SilentArgument + " /NORESTART"
                     $ProcessStartInfo = New-object System.Diagnostics.ProcessStartInfo "msiexec.exe"
                     $ProcessStartInfo.Arguments              = $MSIArguments 
                     $ProcessStartInfo.CreateNoWindow         = $false 
                     $ProcessStartInfo.UseShellExecute        = $false 
                     $ProcessStartInfo.RedirectStandardOutput = $false 
                     $ProcessStartInfo.RedirectStandardError  = $false
                     $Process = New-Object System.Diagnostics.Process 
                     $Process.StartInfo = $ProcessStartInfo 
                     $Process.Start() | Out-Null
                     $Process.WaitForExit()
                     #endregion Patch Execution
                     
                     #region Patch Validation
                     If (
                          #If there is an exit code, and not one of successful codes listed in $MSISuccessCodes...
                          ($Process.ExitCode) -and
                          !($MSISuccessCodes -contains $Process.ExitCode)
                         ){
                            Write-Log ("FAILURE: Installer ""$MSI"". Patch $PatchNumber of $PatchCountTotal. Failed with ExitCode:" + $Process.ExitCode)
                            Exit $Process.ExitCode
                           }
                     If (
                          $Process.ExitCode -eq 1639
                         ){
                            Write-Log "   INFO: Installer""$MSI"". Patch $PatchNumber of $PatchCountTotal. Is already installed."
                            If ($MSPatchRegistryKey){
                                                     $PKB = $MSI.BaseName
                                                     If (
                                                          !(Test-Path -Path $MSPatchRegistryKey)
                                                         ){
                                                            New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                           }
                                                     else {
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                           }
                                                     If (
                                                          (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                         ){
                                                           Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                           }
                                                     }
                            Remove-Item -Path ($MSI.FullName) -Force                          
                           }
                     If (
                          $Process.ExitCode -eq 3010
                         ){
                            Write-Log "SUCCESS: Installer ""$MSI"" installed correctly, but requires reboot for completion."
                            If ($MSPatchRegistryKey){
                                                     $PKB = $MSI.BaseName
                                                     If (
                                                          !(Test-Path -Path $MSPatchRegistryKey)
                                                         ){
                                                            New-Item -Path $MSPatchRegistryKey -Force  | Out-Null
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                           }
                                                     else {
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force  | Out-Null
                                                           }
                                                     If (
                                                          (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                         ){
                                                           Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                           }
                                                     }
                            Remove-Item -Path ($MSI.FullName) -Force 
                           }
                     If (
                          $Process.ExitCode -eq 0
                         ){
                            Write-Log "SUCCESS: Installed $MSI"
                            If ($MSPatchRegistryKey){
                                                     $PKB = $MSI.BaseName
                                                     If (
                                                          !(Test-Path -Path $MSPatchRegistryKey)
                                                         ){
                                                            New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                           }
                                                     else {
                                                            New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                           }
                                                     If (
                                                          (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                         ){
                                                           Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                           }
                                                     }
                            Remove-Item -Path ($MSI.FullName) -Force 
                           }
                     #endregion Patch Validation
                    }
      }

#endregion MSI Installers

#region CAB Installations

       Foreach (
                 $CABFile in (Get-ChildItem -Path $MSPatchFolder -Recurse | Where-Object { $_.Extension -match '.CAB'})
                ){
                   $PatchNumber++
                   Write-Log "   INFO: Installing ""$CABFile"". Patch $PatchNumber of $PatchCountTotal"
                   If (
                       ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer').SvcVersion -match '11.0.9600') -and
                       $CABFile.Name -match 'IE-Win7'
                       ){
                          Write-Log "   INFO: ""$CABFile"" is already installed. SKipping $PatchNumber of $PatchCountTotal"
                         }
                   else {
                            $PKB = $CABFile.BaseName -replace 'Windows6.1-' -replace '-x86' -replace '.cab'
                            $Arguments = @("/ip","/m:""$($CABFile.FullName)""","/quiet","/norestart")
                            $SuccessCodes = @("0","1639","3010")
                            $ProcessStartInfo = New-object System.Diagnostics.ProcessStartInfo
                            $ProcessStartInfo.FileName = "C:\Windows\System32\PkgMgr.exe"
                            $ProcessStartInfo.Arguments              = $Arguments 
                            $ProcessStartInfo.CreateNoWindow         = $false 
                            $ProcessStartInfo.UseShellExecute        = $false 
                            $ProcessStartInfo.RedirectStandardOutput = $false 
                            $ProcessStartInfo.RedirectStandardError  = $false
                            $Process = New-Object System.Diagnostics.Process 
                            $Process.StartInfo = $ProcessStartInfo 
                            $Process.Start() | Out-Null
                            $Process.WaitForExit()
                           If (
                                #If there is an exit code, and not one of successful codes listed in $MSISuccessCodes...
                                (![String]::IsNullOrEmpty($Process.ExitCode)) -and
                                !($SuccessCodes -contains $Process.ExitCode)
                               ){
                                  Write-Log ("FAILURE: CAB File ""$CABFile"". Patch $PatchNumber of $PatchCountTotal. Failed with ExitCode:" + $Process.ExitCode)
                                  Exit $Process.ExitCode
                                 }
                           If ($Process.ExitCode -eq 1639){
                                                              Write-Log "   INFO: CAB File ""$CABFile"". Patch $PatchNumber of $PatchCountTotal. Is already installed."
                                                              Remove-Item -Path ($CABFile.FullName | Split-Path -Parent) -Recurse -Force
                                                            }
                           If ($Process.ExitCode -eq 3010){
                                                            Write-Log "SUCCESS: CAB File ""$CABFile"" installed correctly, but requires reboot for completion."
                                                            If ($MSPatchRegistryKey){
                                                                                      $PKB = $CABFile.BaseName
                                                                                      If (
                                                                                           !(Test-Path -Path $MSPatchRegistryKey)
                                                                                          ){
                                                                                             New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                             New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                            }
                                                                                      else {
                                                                                             New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                            }
                                                                                      If (
                                                                                           (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                          ){
                                                                                            Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                            }
                                                                                     }
                                                            Remove-Item -Path ($CABFile.FullName | Split-Path -Parent) -Recurse -Force
                                 }
                           If ($Process.ExitCode -eq 0){
                                                        Write-Log "SUCCESS: Installed $CABFile"
                                                        If ($MSPatchRegistryKey){
                                                                                    $PKB = $CABFile.BaseName
                                                                                    If (
                                                                                        !(Test-Path -Path $MSPatchRegistryKey)
                                                                                        ){
                                                                                        New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                        New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                        }
                                                                                    else {
                                                                                        New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                        }
                                                                                    If (
                                                                                        (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                        ){
                                                                                        Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                        }
                                                                                   }
                                                        Remove-Item -Path ($CABFile.FullName | Split-Path -Parent) -Recurse -Force 
                                 }
                         }
                  }

#endregion CAB Installations

#region EXE executables.
IF (
     !!(Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Extension -match '.exe' } | Where-Object {$_.Name -notmatch "NDP"})
    ){
        Write-Log "   INFO: Found "".EXE"" executables to be ran."
        Write-Host -Object ""
        Write-Log "   INFO: Proceeding with EXE executables..."
        Foreach (
                  $EXE in ((Get-ChildItem -Path $MSPatchFolder | Where-Object { $_.Extension -match '.exe' } | Where-Object {$_.Name -notmatch "NDP"}) | Sort-Object)
                 ){
                    $PatchNumber++
                    $EXEFullName = ($EXE.Fullname)
                    Write-Host -Object ""
                    Write-Log "   INFO: Executing $EXE. Patch $PatchNumber of $PatchCountTotal"
                    $ProcessStartInfo = New-object System.Diagnostics.ProcessStartInfo 
                    $ProcessStartInfo.CreateNoWindow = $false 
                    $ProcessStartInfo.UseShellExecute = $false 
                    $ProcessStartInfo.RedirectStandardOutput = $false 
                    $ProcessStartInfo.RedirectStandardError = $false
                    $ProcessStartInfo.FileName = $EXEFullName 
                    $ProcessStartInfo.Arguments = @("/Q") 
                    $process = New-Object System.Diagnostics.Process 
                    $process.StartInfo = $ProcessStartInfo 
                    [void]$process.Start()
                    $process.WaitForExit()
                    If ($process.ExitCode -eq 0){
                                                    Write-Log "SUCCESS: Executed $EXE"
                                                    If ($MSPatchRegistryKey){
                                                                                $PKB = $EXE.BaseName
                                                                                If (
                                                                                    !(Test-Path -Path $MSPatchRegistryKey)
                                                                                    ){
                                                                                    New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                    New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                    }
                                                                                else {
                                                                                    New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                    }
                                                                                If (
                                                                                    (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                    ){
                                                                                    Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                    }
                                                                                }
                                                    Remove-Item -Path ($EXE.FullName) -Force 

                          }
                    If ($process.ExitCode -eq 3010){
                                                    Write-Log ("   INFO: Executed '$EXE'. But it has exited with an exit code of 3010. A reboot will be required.")
                                                    If ($MSPatchRegistryKey){
                                                                                $PKB = $EXE.BaseName
                                                                                If (
                                                                                    !(Test-Path -Path $MSPatchRegistryKey)
                                                                                    ){
                                                                                    New-Item -Path $MSPatchRegistryKey -Force | Out-Null
                                                                                    New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                    }
                                                                                else {
                                                                                    New-ItemProperty -Path $MSPatchRegistryKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
                                                                                    }
                                                                                If (
                                                                                    (Get-ItemProperty -Path $MSPatchRegistryKey).$PKB -eq 'Installed'
                                                                                    ){
                                                                                    Write-Log "   INFO: Registered ""$MSPatchRegistryKey"" Property: ""$PKB"" Value: ""Installed""."
                                                                                    }
                                                                                }
                                                    Remove-Item -Path ($EXE.FullName) -Force 
                           }
                    elseif (
                             ($process.ExitCode -gt 0)
                            ) {
                                Write-Log ("FAILURE: Unable to execute '$EXE' exited with a non-success exit code. Please Investigate ExitCode:" + $process.ExitCode)
                                Exit $process.ExitCode
                               }
                    }
       }
#endregion EXE Executables

#region Revert CRL for .Net Installers
Write-Log "   INFO: Reverting Dot Net offline install registry key value."
$CRLReg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing'
$CRLKey = 'State'
If (
     (Get-ItemProperty -Path $CRLReg).State -notmatch $OldCrlValue
    ) {
        Write-Log "   INFO: The Registry Key: ""$CRLReg"" PropertyName: ""$CRLKey"" does not match original value"
        Write-Log "   INFO: Reverting the change."
        Start-Sleep -Milliseconds 500
        Write-Host -Object ""
        Set-ItemProperty -Path $CRLReg -Name $CRLKey -Value $OldCrlValue
        If (
             (Get-ItemProperty -Path $CRLReg).State -match $OldCrlValue
            ){
               Write-Log "   INFO: Reverted the value for $CRLKey"
               Start-Sleep -Milliseconds 500
              }
       }
#endregion Revert CRL for .Net Installers