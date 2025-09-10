Function UnusedApps {
    Function Silent {
        $Global:ProgressPreference = 'SilentlyContinue'
    }

    # Remove Apps 
    Function UninstallThirdPartyBloat {
        Write-Host `n"Uninstalling Default Third Party Applications..." -NoNewline
            
        $UninstallAppxPackages = 
        "Microsoft.WindowsAlarms", #Alarm and clock app for Windows.
        "Microsoft.549981C3F5F10", #Code likely represents a specific app or service, specifics unknown without context.
        "Microsoft.WindowsFeedbackHub", #Platform for user feedback on Windows.
        "Microsoft.Bing*", #Bing search engine related services and apps.
        "Microsoft.Zune*", #Media software for music and videos, now discontinued.
        "Microsoft.PowerAutomateDesktop", #Automation tool for desktop workflows.
        "Microsoft.WindowsSoundRecorder", #Audio recording app for Windows.
        "Microsoft.MicrosoftSolitaireCollection", #Solitaire game collection.
        "Microsoft.GamingApp", #Likely related to Xbox or Windows gaming services.
        "*microsoft.windowscomm**", #Likely refers to communication services in Windows, specifics unclear.
        "MicrosoftCorporationII.QuickAssist", #Remote assistance app by Microsoft.
        "Microsoft.Todos", #Task management app.
        "Microsoft.SkypeApp", #Skype communication app for Windows.
        "Microsoft.Microsoft3DViewer", #App for viewing 3D models.
        "Microsoft.Wallet", #Digital wallet app, now discontinued.
        "Microsoft.WebMediaExtensions", #Extensions for media formats in web browsers.
        "MicrosoftWindows.Client.WebExperience", #Likely related to the web browsing experience in Windows, specifics unclear.
        "Clipchamp.Clipchamp", #Video editing app.
        "Microsoft.WindowsMaps", #Mapping and navigation app.
        "Microsoft.Advertising.Xaml", #Advertising SDK for apps.
        "Microsoft.MixedReality.Portal", #Mixed Reality portal app for immersive experiences.
        "Microsoft.BingNews", #News aggregation app.
        "Microsoft.GetHelp", #Support and troubleshooting app.
        "Microsoft.Getstarted", #Introduction and tips app for Windows features.
        "Microsoft.MicrosoftOfficeHub", #Central hub for Office apps and services.
        "Microsoft.OneConnect", #Connectivity and cloud services app.
        "Microsoft.People", #Contact management and social integration app.
        "Microsoft.Xbox.TCUI", #Xbox text, chat, and user interface services.
        "Microsoft.XboxApp", #Main app for Xbox social and gaming features.
        "Microsoft.XboxGameOverlay", #In-game overlay for Xbox features and social interactions.
        "Microsoft.XboxIdentityProvider", #Service for Xbox account authentication.
        "Microsoft.XboxSpeechToTextOverlay" #Speech-to-text services for Xbox gaming.
        
        $installedApps = Get-AppxPackage -AllUsers
            
        Silent #silently
            
        foreach ($package in $UninstallAppxPackages) {
            $app = $installedApps | Where-Object { $_.Name -like $package }
            if ($null -ne $app) {
                try {
                    $app | Remove-AppxPackage -ErrorAction Stop
                }
                catch {
                    Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                }
            }
        }
        
        # Uninstall Microsoft Teams Outlook Add-in
        $TeamsAddinGUID = '{A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91}'
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$TeamsAddinGUID"
        if (Test-Path $registryPath) {
            try {
                Start-Process msiexec.exe -ArgumentList "/x $TeamsAddinGUID /qn /norestart" -NoNewWindow -Wait
            }
            catch {
                Write-Host "[WARNING] $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
            }
        }
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
        
    UninstallThirdPartyBloat

    # Uninstall Windows Media Player
    Function UninstallMediaPlayer {
        Write-Host "Uninstalling Windows Media Player..." -NoNewline
        try {
            Silent #silently
            Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
            Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    }

    UninstallMediaPlayer

    # Uninstall Work Folders Client - Not applicable to Server
    Function UninstallWorkFolders {
        Write-Host "Uninstalling Work Folders Client..." -NoNewline
        try {
            Silent #silently
            Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    }

    UninstallWorkFolders

    # Uninstall Microsoft XPS Document Writer 
    Function UninstallXPSPrinter {
        Write-Host "Uninstalling Microsoft XPS Document Writer..." -NoNewline
        try {
            Remove-Printer -Name "Microsoft XPS Document Writer" -ErrorAction SilentlyContinue 
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    }

    UninstallXPSPrinter

    # Remove Default Fax Printer 
    Function RemoveFaxPrinter {
        Write-Host "Removing Default Fax Printer..." -NoNewline
        try {
            Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    }

    RemoveFaxPrinter

    # Uninstall Windows Fax and Scan Services - Not applicable to Server
    Function UninstallFaxAndScan {
        Write-Host "Uninstalling Windows Fax and Scan Services..." -NoNewline
        try {
            Silent #silently
            Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
            Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black 
    }

    UninstallFaxAndScan

    # Block Microsoft Edge telemetry
    Function EdgePrivacySettings {
        Write-Host "Adjusting Microsoft Edge privacy settings..." -NoNewline
            
        $EdgePrivacyCUPath = "HKCU:\Software\Policies\Microsoft\Edge"
        $EdgePrivacyAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        
        $EdgePrivacyKeys = @(
            "PaymentMethodQueryEnabled",
            "PersonalizationReportingEnabled",
            "AddressBarMicrosoftSearchInBingProviderEnabled",
            "UserFeedbackAllowed",
            "AutofillCreditCardEnabled",
            "AutofillAddressEnabled",
            "LocalProvidersEnabled",
            "SearchSuggestEnabled",
            "EdgeShoppingAssistantEnabled",
            "WebWidgetAllowed",
            "HubsSidebarEnabled"
        )
        
        $EdgePrivacyKeys | ForEach-Object {
            if (-not (Test-Path $EdgePrivacyCUPath)) {
                New-Item -Path $EdgePrivacyCUPath -Force *>$null
            }
            try {
                Set-ItemProperty -Path $EdgePrivacyCUPath -Name $_ -Value 0
                Set-ItemProperty -Path $EdgePrivacyCUPath -Name "ConfigureDoNotTrack" -Value 1
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        $EdgePrivacyAUKeys = @(
            "DoNotTrack",
            "QuicAllowed",
            "SearchSuggestEnabled",
            "AllowSearchAssistant",
            "FormFillEnabled",
            "PaymentMethodQueryEnabled",
            "PersonalizationReportingEnabled",
            "AddressBarMicrosoftSearchInBingProviderEnabled",
            "UserFeedbackAllowed",
            "AutofillCreditCardEnabled",
            "AutofillAddressEnabled",
            "LocalProvidersEnabled",
            "SearchSuggestEnabled",
            "EdgeShoppingAssistantEnabled",
            "WebWidgetAllowed",
            "HubsSidebarEnabled"
        )
        
        $EdgePrivacyAUKeys | ForEach-Object {
            if (-not (Test-Path $EdgePrivacyAUPath)) {
                New-Item -Path $EdgePrivacyAUPath -Force *>$null
            }
            try {
                Set-ItemProperty -Path $EdgePrivacyAUPath -Name $_ -Value 0
                Set-ItemProperty -Path $EdgePrivacyAUPath -Name "ConfigureDoNotTrack" -Value 1
            }
            catch {
                Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
        
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
        
    EdgePrivacySettings

    Function OfficePrivacySettings {
        Write-Host "Adjusting Microsoft Office privacy settings..." -NoNewline
        $OfficePrivacyRegistryKeys = @{
            "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry"          = @{
                "DisableTelemetry" = 1
            }
            "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" = @{
                "SendTelemetry" = 3
            }
            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common"            = @{
                "QMEnable" = 0;
                "LinkedIn" = 0
            }
            "HKCU:\Software\Microsoft\Office\16.0\Common\MailSettings"        = @{
                "InlineTextPrediction" = 0
            }
            "HKCU:\Software\Policies\Microsoft\Office\16.0\osm"               = @{
                "Enablelogging"         = 0;
                "EnableUpload"          = 0;
                "EnableFileObfuscation" = 1
            }
            "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback"   = @{
                "SurveyEnabled" = 0;
                "Enabled"       = 0;
                "IncludeEmail"  = 0
            }
        }
        
        foreach ($key in $OfficePrivacyRegistryKeys.GetEnumerator()) {
            $registryPath = $key.Key
            $registryValues = $key.Value
        
            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force *>$null
            }
        
            foreach ($valueName in $registryValues.GetEnumerator()) {
                $value = $valueName.Key
                $data = $valueName.Value
        
                try {
                    Set-ItemProperty -Path $registryPath -Name $value -Value $data
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
        }
        
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
        
    OfficePrivacySettings  
        
    Function DisableWindowsSync {
        Write-Host "Disabling Windows Sync..." -NoNewline
        $WindowsSyncRegistryKeys = @{
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"                        = @{
                "SyncPolicy" = 5
            }
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" = @{
                "Enabled" = 0
            }
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" = @{
                "Enabled" = 0
            }
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"     = @{
                "Enabled" = 0
            }
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"        = @{
                "Enabled" = 0
            }
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility"   = @{
                "Enabled" = 0
            }
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows"         = @{
                "Enabled" = 0
            }
        }
        
        foreach ($key in $WindowsSyncRegistryKeys.GetEnumerator()) {
            $registryPath = $key.Key
            $registryValues = $key.Value
        
            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force *>$null
            }
        
            foreach ($valueName in $registryValues.GetEnumerator()) {
                $value = $valueName.Key
                $data = $valueName.Value
        
                try {
                    Set-ItemProperty -Path $registryPath -Name $value -Value $data
                }
                catch {
                    Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                }
            }
        }
        
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
        
    DisableWindowsSync        

    Function DisableWidgets {
        Write-Host "Disabling Windows Widgets..." -NoNewline
        try {
            Get-AppxPackage -AllUsers -Name *WebExperience* | Remove-AppxPackage -AllUsers *>$null
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        } 
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
    
    }

    DisableWidgets

    # Disable Copilot
    Function DisableCopilot {
        Write-Host "Disabling Microsoft Copilot..." -NoNewline
                
        $registryPath = "HKCU:\Software\Policies\Microsoft\Windows"
        $registryName = "WindowsCopilot"
        $registryProperty = "TurnOffWindowsCopilot"
        $edgeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        $explorerRegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Name $registryName -Force *>$null
        }
                
        New-ItemProperty -Path $registryPath\$registryName -Name $registryProperty -Value 1 -PropertyType DWORD -Force *>$null
                
        if (-not (Test-Path $edgeRegistryPath)) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\" -Name "Edge" -Force *>$null
        }
                
        New-ItemProperty -Path $edgeRegistryPath -Name "HubsSidebarEnabled" -Value 0 -PropertyType DWORD -Force *>$null
        
        # Remove Copilot button from File Explorer
        Set-ItemProperty -Path $explorerRegistryPath -Name "ShowCopilotButton" -Value 0 -Force *>$null
                
        $lmRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
        $wowRegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows"
                
        if (-not (Test-Path $lmRegistryPath\$registryName)) {
            New-Item -Path $lmRegistryPath -Name $registryName -Force *>$null
        }
                
        Set-ItemProperty -Path $lmRegistryPath\$registryName -Name $registryProperty -Value 1 -Force *>$null
        
        if (-not (Test-Path $wowRegistryPath\$registryName)) {
            New-Item -Path $wowRegistryPath -Name $registryName -Force *>$null
        }
                
        Set-ItemProperty -Path $wowRegistryPath\$registryName -Name $registryProperty -Value 1 -Force *>$null

        $currentSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
        If (-not (Test-Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows\WindowsCopilot")) {
            New-Item -Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows" -Name "WindowsCopilot" -Force *>$null
        }
        Set-ItemProperty -Path "HKU:\$currentSID\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
        
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

    }
        
    DisableCopilot        

    # Uninstall OneDrive
    Function UninstallOneDrive {
        Write-Host "Removing Microsoft OneDrive..." -NoNewline
        Silent #silently
        try {
            # Stop OneDrive and Explorer processes
            taskkill /f /im OneDrive.exe *>$null

            # Uninstall OneDrive
            $OneDriveSetupPaths = @(
                "$env:systemroot\System32\OneDriveSetup.exe",
                "$env:systemroot\SysWOW64\OneDriveSetup.exe"
            )

            foreach ($Path in $OneDriveSetupPaths) {
                if (Test-Path $Path) {
                    & $Path /uninstall
                }
            }

            $OneDriveFolders = @(
                "$env:localappdata\Microsoft\OneDrive",
                "$env:programdata\Microsoft OneDrive",
                "$env:systemdrive\OneDriveTemp",
                "$env:userprofile\OneDrive"
            )

            $OneDriveFolders | ForEach-Object {
                Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue
            }

            New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
            $OneDriveClsid = "{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
            $ClsidPaths = @(
                "HKCR:\CLSID\$OneDriveClsid",
                "HKCR:\Wow6432Node\CLSID\$OneDriveClsid"
            )

            foreach ($Path in $ClsidPaths) {
                if (-not (Test-Path $Path)) {
                    New-Item -Path $Path -Force | Out-Null
                    Set-ItemProperty -Path $Path -Name "System.IsPinnedToNameSpaceTree" -Value 0
                }
            }

            If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive") {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
            }

            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force -ErrorAction SilentlyContinue

            # Remove OneDrive from the registry
            reg load "HKU\Default" "C:\Users\Default\NTUSER.DAT" *>$null
            reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f *>$null
            reg unload "HKU\Default" *>$null
                    
            Remove-Item -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "env:userprofile\Desktop\OneDrive.lnk" -Force -ErrorAction SilentlyContinue

            Start-Sleep 3
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black

        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
                

    }
        
    UninstallOneDrive

    # Disable Edge desktop shortcut creation after certain Windows updates are applied 
    Function UninstallEdge {
        Write-Host "Removing Microsoft Edge..." -NoNewline

        try {
            $ProgressPreference = 'SilentlyContinue'
            $sys32 = [Environment]::GetFolderPath('System')
            $windir = [Environment]::GetFolderPath('Windows')
            $env:path = "$windir;$sys32;$sys32\Wbem;$sys32\WindowsPowerShell\v1.0;" + $env:path
            $baseKey = 'HKLM:\SOFTWARE' + $(if ([Environment]::Is64BitOperatingSystem) { '\WOW6432Node' }) + '\Microsoft'
            $msedgeExe = "$([Environment]::GetFolderPath('ProgramFilesx86'))\Microsoft\Edge\Application\msedge.exe"
            $edgeUWP = "$windir\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"

            function DeleteIfExist($Path) {
                if (Test-Path $Path) {
                    Remove-Item -Path $Path -Force -Recurse -Confirm:$false 2>$null
                }
            }

            function Get-MsiexecAppByName {
                param(
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()]
                    [string]$Name
                )

                $uninstallKeyPath = 'Microsoft\Windows\CurrentVersion\Uninstall'
                $uninstallKeys = (Get-ChildItem -Path @(
                        "HKLM:\SOFTWARE\$uninstallKeyPath",
                        "HKLM:\SOFTWARE\WOW6432Node\$uninstallKeyPath",
                        "HKCU:\SOFTWARE\$uninstallKeyPath",
                        "HKCU:\SOFTWARE\WOW6432Node\$uninstallKeyPath"
                    ) -EA SilentlyContinue) -match '\{\b[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}\b\}'

                $edges = @()
                foreach ($key in $uninstallKeys.PSPath) {
                    if (((Get-ItemProperty -Path $key -EA 0).DisplayName -like "*$Name*") -and ((Get-ItemProperty -Path $key -EA 0).UninstallString -like '*MsiExec.exe*')) {
                        $edges += Split-Path -Path $key -Leaf
                    }
                }

                return $edges
            }

            function EdgeInstalled {
                Test-Path $msedgeExe
            }

            function KillEdgeProcesses {
                $ErrorActionPreference = 'SilentlyContinue'
                foreach ($service in (Get-Service -Name '*edge*' | Where-Object { $_.DisplayName -like '*Microsoft Edge*' }).Name) {
                    Stop-Service -Name $service -Force 2>$null
                }
                foreach (
                    $process in
                    (Get-Process | Where-Object { ($_.Path -like "$([Environment]::GetFolderPath('ProgramFilesX86'))\Microsoft\*") -or ($_.Name -like '*msedge*') }).Id
                ) {
                    Stop-Process -Id $process -Force 2>$null
                }
                $ErrorActionPreference = 'Continue'	
            }

            function RemoveEdgeChromium {
                $msis = Get-MsiexecAppByName -Name 'Microsoft Edge'

                function UninstallStringFail {
                    $script:edgeUninstallers = @()
                    'LocalApplicationData', 'ProgramFilesX86', 'ProgramFiles' | ForEach-Object {
                        $folder = [Environment]::GetFolderPath($_)
                        $script:edgeUninstallers += Get-ChildItem "$folder\Microsoft\Edge*\setup.exe" -Recurse -EA 0 |
                        Where-Object { ($_ -like '*Edge\Application*') -or ($_ -like '*SxS\Application*') }
                    }
                }

                $uninstallKeyPath = "$baseKey\Windows\CurrentVersion\Uninstall\Microsoft Edge"
                $uninstallString = (Get-ItemProperty -Path $uninstallKeyPath -EA 0).UninstallString
                if ([string]::IsNullOrEmpty($uninstallString) -and ($msis.Count -le 0)) {
                    $uninstallString = $null
                    UninstallStringFail
                }
                else {
                    $uninstallPath, $uninstallArgs = $uninstallString -split '"', 3 |
                    Where-Object { $_ } |
                    ForEach-Object { [System.Environment]::ExpandEnvironmentVariables($_.Trim()) }

                    if (![System.IO.Path]::IsPathRooted($uninstallPath) -or !(Test-Path $uninstallPath -PathType Leaf)) {
                        $uninstallPath = $null
                        UninstallStringFail
                    }
                }

                if (($msis.Count -le 0) -and ($script:edgeUninstallers.Count -le 0) -and !$uninstallPath) {
                    exit 2
                }

                function ToggleEURegion([bool]$Enable) {
                    $geoKey = 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International\Geo'

                    $values = @{
                        'Name'   = 'FR'
                        'Nation' = '84'
                    }
                    $geoChange = 'EdgeSaved'

                    if ($Enable) {
                        $values.GetEnumerator() | ForEach-Object {
                            Rename-ItemProperty -Path $geoKey -Name $_.Key -NewName "$($_.Key)$geoChange" -Force -EA 0
                            Set-ItemProperty -Path $geoKey -Name $_.Key -Value $_.Value -Force
                        }
                    }
                    else {
                        $values.GetEnumerator() | ForEach-Object {
                            Remove-ItemProperty -Path $geoKey -Name $_.Key -Force -EA 0
                            Rename-ItemProperty -Path $geoKey -Name "$($_.Key)$geoChange" -NewName $_.Key -Force -EA 0
                        }
                    }
                }

                function ModifyRegionJSON {
                    $cleanup = $false
                    $script:integratedServicesPath = "$sys32\IntegratedServicesRegionPolicySet.json"

                    if (Test-Path $integratedServicesPath) {
                        $cleanup = $true
                        try {
                            $admin = [System.Security.Principal.NTAccount]$(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value

                            $acl = Get-Acl -Path $integratedServicesPath
                            $script:backup = [System.Security.AccessControl.FileSecurity]::new()
                            $script:backup.SetSecurityDescriptorSddlForm($acl.Sddl)
                            $acl.SetOwner($admin)
                            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admin, 'FullControl', 'Allow')
                            $acl.AddAccessRule($rule)
                            Set-Acl -Path $integratedServicesPath -AclObject $acl

                            $integratedServices = Get-Content $integratedServicesPath | ConvertFrom-Json
                            ($integratedServices.policies | Where-Object { ($_.'$comment' -like '*Edge*') -and ($_.'$comment' -like '*uninstall*') }).defaultState = 'enabled'
                            $modifiedJson = $integratedServices | ConvertTo-Json -Depth 100

                            $script:backupIntegratedServicesName = "IntegratedServicesRegionPolicySet.json.$([System.IO.Path]::GetRandomFileName())"
                            Rename-Item $integratedServicesPath -NewName $script:backupIntegratedServicesName -Force
                            Set-Content $integratedServicesPath -Value $modifiedJson -Force -Encoding UTF8
                        }
                        catch {}
                    }

                    return $cleanup
                }

                function UninstallEdge {
                    foreach ($msi in $msis) {
                        Start-Process -FilePath 'msiexec.exe' -ArgumentList "/qn /X$(Split-Path -Path $msi -Leaf) REBOOT=ReallySuppress /norestart" -Wait -WindowStyle Hidden
                    }

                    if ($uninstallPath) {
                        Start-Process -Wait -FilePath $uninstallPath -ArgumentList "$uninstallArgs --force-uninstall" -WindowStyle Hidden
                    }
                    else {
                        foreach ($setup in $edgeUninstallers) {
                            if (Test-Path $setup) {
                                $sulevel = ('--system-level', '--user-level')[$setup -like '*\AppData\Local\*']
                                Start-Process -Wait $setup -ArgumentList "--uninstall --msedge $sulevel --channel=stable --verbose-logging --force-uninstall" -WindowStyle Hidden
                            }
                        }
                    }

                    return EdgeInstalled
                }

                function GlobalRemoveMethods {
                    Remove-ItemProperty -Path "$baseKey\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Name 'experiment_control_labels' -Force -EA 0

                    $devKeyPath = "$baseKey\EdgeUpdateDev"
                    if (!(Test-Path $devKeyPath)) { New-Item -Path $devKeyPath -ItemType 'Key' -Force | Out-Null }
                    Set-ItemProperty -Path $devKeyPath -Name 'AllowUninstall' -Value '' -Type String -Force
	
                    KillEdgeProcesses
                }

                $fail = $true
                $method = 1
                while ($fail) {
                    switch ($method) {
                        1 {
                            GlobalRemoveMethods
                            if (!(Test-Path "$edgeUWP\MicrosoftEdge.exe")) {
                                New-Item $edgeUWP -ItemType Directory -ErrorVariable cleanup -EA 0 | Out-Null
                                New-Item "$edgeUWP\MicrosoftEdge.exe" -EA 0 | Out-Null
                                $cleanup = $true
                            }

                            $fail = UninstallEdge

                            if ($cleanup) {
                                Remove-Item $edgeUWP -Force -EA 0 -Recurse
                            }
                        }

                        2 {
                            GlobalRemoveMethods
                            $envPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
                            try {
                                Set-ItemProperty -Path $envPath -Name 'windir' -Value '' -Type ExpandString
                                $env:windir = [System.Environment]::GetEnvironmentVariable('windir', [System.EnvironmentVariableTarget]::Machine)

                                $fail = UninstallEdge
                            }
                            finally {
                                Set-ItemProperty -Path $envPath -Name 'windir' -Value '%SystemRoot%' -Type ExpandString
                            }
                        }

                        3 {
                            GlobalRemoveMethods
                            ToggleEURegion $true

                            $fail = UninstallEdge

                            ToggleEURegion $false
                        }

                        4 {
                            GlobalRemoveMethods
                            $cleanup = ModifyRegionJSON
				
                            $fail = UninstallEdge

                            if ($cleanup) {
                                Remove-Item $integratedServicesPath -Force -EA 0
                                Rename-Item "$sys32\$backupIntegratedServicesName" -NewName $integratedServicesPath -Force -EA 0
                                Set-Acl -Path $integratedServicesPath -AclObject $backup -EA 0
                            }
                        }

                        default {
                            exit 3
                        }
                    }

                    $method++
                }

                "$([Environment]::GetFolderPath('Desktop'))\Microsoft Edge.lnk",
                "$([Environment]::GetFolderPath('CommonStartMenu'))\Microsoft Edge.lnk" | ForEach-Object { DeleteIfExist $_ }

                if ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -EA 0).'ShowCopilotButton' -eq 1) {
                    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
                }
            }

            function RemoveEdgeAppX {
                $SID = (New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([Security.Principal.SecurityIdentifier]).Value

                $appxStore = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
                $pattern = "HKLM:$appxStore\InboxApplications\Microsoft.MicrosoftEdge_*_neutral__8wekyb3d8bbwe"
                $edgeAppXKey = (Get-Item -Path $pattern -EA 0).PSChildName
                if (Test-Path "$pattern") { reg delete "HKLM$appxStore\InboxApplications\$edgeAppXKey" /f 2>$null | Out-Null }

                New-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force -EA 0 | Out-Null
                Get-AppxPackage -Name Microsoft.MicrosoftEdge -EA 0 | Remove-AppxPackage -EA 0 | Out-Null
                Remove-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force -EA 0 | Out-Null
            }

            if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') {
                exit 1
            }

            if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                Start-Process cmd "/c PowerShell -NoP -EP Bypass -File `"$PSCommandPath`"" -Verb RunAs -WindowStyle Hidden
                exit
            }

            RemoveEdgeChromium

            if ($null -ne (Get-AppxPackage -Name Microsoft.MicrosoftEdge -EA 0)) {
                RemoveEdgeAppX
            }

            # Remove Edge tasks
            $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*edge*" }

            # Block Updates
            if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') {
                Write-Status "This script can't be ran as TrustedInstaller/SYSTEM.
Please relaunch this script under a regular admin account." -Level Critical -Exit
            }
            else {
                if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                    if ($PSBoundParameters.Count -le 0 -and !$args) {
                        Start-Process cmd "/c PowerShell -NoP -EP Bypass -File `"$PSCommandPath`"" -Verb RunAs
                        exit
                    }
                    else {
                        throw "This script must be run as an administrator."
                    }
                }
            }

            'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate', 'HKCU:\SOFTWARE\Policies\Microsoft\EdgeUpdate' | % {
                Remove-Item -Path $_ -Recurse -Force -EA 0
                New-Item -Path $_ -Force | Out-Null
            }

            $EdgeUpdateDisabled = "$EdgeRemoverReg\EdgeUpdateDisabled"
            $EdgeUpdateOrchestrator = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\EdgeUpdate'
            if (!(Test-Path $EdgeUpdateOrchestrator) -and (Test-Path $EdgeUpdateDisabled)) {
                Move-Item -Path $EdgeUpdateDisabled -Destination $EdgeUpdateOrchestrator -Force
            }

            # Delete tasks
            foreach ($task in $tasks) {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
            }

        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
        

    }

    UninstallEdge

}

UnusedApps
