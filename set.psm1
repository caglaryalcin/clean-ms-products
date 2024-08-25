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
        "Microsoft.YourPhone", #App linking your phone and PC.
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

    # Delete some folders from This PC
    Function UnpinExplorer {
        Write-Host "Deleting 3D Folders, Pictures, Videos, Music from This PC..." -NoNewline
        $basePath = "HKLM:\SOFTWARE"
        $wow6432Node = "Wow6432Node\"
        $explorerPath = "Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\"
        $quickAccessPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderMSGraph\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}"
        $homePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_36354489\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
        $homePath2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
        $namespaces = @{
            "3DFolders" = "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
            "Videos"    = "{A0953C92-50DC-43bf-BE83-3742FED03C9C}", "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
            "Pictures"  = "{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}", "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
        }
            
        foreach ($category in $namespaces.Keys) {
            foreach ($id in $namespaces[$category]) {
                $paths = @(
                    "$basePath\$explorerPath$id",
                    "$basePath\$wow6432Node$explorerPath$id"
                )
                    
                foreach ($path in $paths) {
                    try {
                        Remove-Item -Path $path -Recurse -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
                    }
                }
            }
        }
        
        # homepath additional settings
        New-Item -Path $homePath2 -Force
        Set-ItemProperty -Path $homePath2 -Name "(Default)" -Value "CLSID_MSGraphHomeFolder"
        Set-ItemProperty -Path $homePath2 -Name "HiddenByDefault" -Value 1 -Type DWord

        # Additional paths
        try {
            Remove-Item -Path $quickAccessPath -Recurse -ErrorAction SilentlyContinue
            Remove-Item -Path $homePath -Recurse -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
            
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    }
        
    UnpinExplorer

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

    # The function is here because programs add themselves to the right click menu after loading
    Function RightClickMenu {
        try {
            Write-Host "Editing the right click menu..." -NoNewline
            # New PS Drives
            New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null

            # Old right click menu
            $regPath = "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
            reg.exe add $regPath /f /ve *>$null
        
            $contextMenuPaths = @(
                "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo", #remove send to
                "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo", #remove send to
                "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing", #remove share
                "HKEY_CLASSES_ROOT\*\shell\pintohomefile", #remove favorites
                #remove give access
                "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing",
                "HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing",
                #remove previous
                "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                "HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}",
                #remove git
                "HKEY_CLASSES_ROOT\Directory\Background\shell\git_gui",
                "HKEY_CLASSES_ROOT\Directory\Background\shell\git_shell",
                #remove treesize
                "HKEY_CLASSES_ROOT\Directory\Background\shell\TreeSize Free",
                "HKEY_CLASSES_ROOT\Directory\Background\shell\VSCode"
            )
        
            foreach ($path in $contextMenuPaths) {
                $regPath = $path -replace 'HKCR:\\', 'HKEY_CLASSES_ROOT\' 
                $cmd = "reg delete `"$regPath`" /f"

                Invoke-Expression $cmd *>$null
            }

            # New hash menu for right click
            $regpath = "HKEY_CLASSES_ROOT\*\shell\hash"
            $sha256menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu"
            $md5menu = "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu"

            reg add $regpath /f *>$null
            reg add $regpath /v "MUIVerb" /t REG_SZ /d HASH /f *>$null
            reg add $regpath /v "SubCommands" /t REG_SZ /d """" /f *>$null
            reg add "$regpath\shell" /f *>$null

            reg add "$sha256menu" /f *>$null
            reg add "$sha256menu\command" /f *>$null
            reg add "$sha256menu" /v "MUIVerb" /t REG_SZ /d SHA256 /f *>$null

            $tempOut = [System.IO.Path]::GetTempFileName()
            $tempErr = [System.IO.Path]::GetTempFileName()
            Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\02menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm SHA256 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
            Remove-Item $tempOut -ErrorAction Ignore
            Remove-Item $tempErr -ErrorAction Ignore

            reg add "$md5menu" /f *>$null
            reg add "$md5menu\command" /f *>$null
            reg add "$md5menu" /v "MUIVerb" /t REG_SZ /d MD5 /f *>$null

            $tempOut = [System.IO.Path]::GetTempFileName()
            $tempErr = [System.IO.Path]::GetTempFileName()
            Start-Process cmd.exe -ArgumentList '/c', 'reg add "HKEY_CLASSES_ROOT\*\shell\hash\shell\03menu\command" /ve /d "powershell -noexit get-filehash -literalpath \"%1\" -algorithm MD5 | format-list" /f' -NoNewWindow -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
            Remove-Item $tempOut -ErrorAction Ignore
            Remove-Item $tempErr -ErrorAction Ignore

            # delete "cast to device" from context menu
            $castpath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
            reg add "$($castpath)" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /d "Play to Menu" /f *>$null

            # Restart Windows Explorer
            taskkill /f /im explorer.exe *>$null
            Start-Sleep 1
            Start-Process "explorer.exe" -ErrorAction Stop
        
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }

        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
    }
        
    RightClickMenu

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
            taskkill /f /im msedge.exe *>$null 2>&1
            taskkill /f /im explorer.exe *>$null 2>&1
        
            # Remove Edge Services
            $edgeservices = "edgeupdate", "edgeupdatem"
            foreach ($service in $edgeservices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -Status stopped -StartupType disabled -ErrorAction SilentlyContinue
                sc.exe delete $service *>$null 2>&1
            }
        
            # Uninstall - Edge
            $regView = [Microsoft.Win32.RegistryView]::Registry32
            $microsoft = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $regView).OpenSubKey('SOFTWARE\Microsoft', $true)
            $edgeClient = $microsoft.OpenSubKey('EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}', $true)
            if ($null -ne $edgeClient.GetValue('experiment_control_labels')) {
                $edgeClient.DeleteValue('experiment_control_labels')
            }
        
            $microsoft.CreateSubKey('EdgeUpdateDev').SetValue('AllowUninstall', '')
        
            $uninstallRegKey = $microsoft.OpenSubKey('Windows\CurrentVersion\Uninstall\Microsoft Edge')
            $uninstallString = $uninstallRegKey.GetValue('UninstallString') + ' --force-uninstall'
            Silent #silently
            Start-Process cmd.exe "/c $uninstallString" -WindowStyle Hidden
        
            $appxStore = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
            $pattern = "HKLM:$appxStore\InboxApplications\Microsoft.MicrosoftEdge_*_neutral__8wekyb3d8bbwe"
            $key = (Get-Item -Path $pattern).PSChildName
            reg delete "HKLM$appxStore\InboxApplications\$key" /f *>$null
        
            #if error use this > $SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $user = "$env:USERDOMAIN\$env:USERNAME"
                    (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value *>$null
            New-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Force *>$null
            Get-AppxPackage -Name Microsoft.MicrosoftEdge | Remove-AppxPackage -ErrorAction SilentlyContinue
            Remove-Item -Path "HKLM:$appxStore\EndOfLife\$SID\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -ErrorAction SilentlyContinue
        
            # Delete additional files
            $additionalFilesPath = "C:\Windows\System32\MicrosoftEdgeCP.exe"
            if (Test-Path -Path $additionalFilesPath) {
                $additionalFiles = Get-ChildItem -Path "C:\Windows\System32\MicrosoftEdge*" -File
                foreach ($file in $additionalFiles) {
                    $takeownArgs = "/f $($file.FullName)"
                    Start-Process -FilePath "takeown.exe" -ArgumentList $takeownArgs -Wait | Out-Null
                    $icaclsArgs = "`"$($file.FullName)`" /inheritance:e /grant `"$($env:UserName)`":(OI)(CI)F /T /C"
                    Start-Process -FilePath "icacls.exe" -ArgumentList $icaclsArgs -Wait | Out-Null
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        
            $keyPath = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate"
            $propertyName = "DoNotUpdateToEdgeWithChromium"
            if (-not (Test-Path $keyPath)) {
                New-Item -Path $keyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $keyPath -Name $propertyName -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        
            taskkill /f /im "MicrosoftEdgeUpdate.exe" *>$null
        
            $edgeDirectories = Get-ChildItem -Path "C:\Program Files (x86)\Microsoft" -Filter "Edge*" -Directory -ErrorAction SilentlyContinue
            if ($edgeDirectories) {
                $edgeDirectories | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            }
        
            $progressPreference = 'SilentlyContinue'
            Get-AppxPackage -AllUsers Microsoft.Edge | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
        
            $paths = @(
                "C:\Program Files (x86)\Microsoft\*edge*",
                "C:\Program Files (x86)\Microsoft\Edge",
                "C:\Program Files (x86)\Microsoft\Temp",
                "C:\Program Files (x86)\Microsoft\*"
            )
        
            foreach ($path in $paths) {
                $items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue
                if ($items) {
                    Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue *>$null
                }
            }
        
            # Final check if Edge is still installed
            if (!(Get-Process "msedge" -ErrorAction SilentlyContinue)) {
                Start-Process explorer.exe -NoNewWindow
                Start-Sleep 4
                Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            }
            else {
                throw "Microsoft Edge process is still running."
            }

            # Delete the lnk files in the taskbar
            $taskBarPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
            $taskBarPath1 = "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\"
            $taskBarPath2 = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
            $shortcuts = "Microsoft Edge.lnk", "Microsoft Teams classic.lnk"

            $shortcuts | ForEach-Object {
                $fullPath1 = Join-Path $taskBarPath $_
                $fullPath2 = Join-Path $taskBarPath1 $_
                $fullPath3 = Join-Path $taskBarPath2 $_

                if (Test-Path $fullPath1) {
                    Remove-Item $fullPath1 -ErrorAction Stop
                }

                if (Test-Path $fullPath2) {
                    Remove-Item $fullPath2 -ErrorAction Stop
                }

                if (Test-Path $fullPath3) {
                    Remove-Item $fullPath3 -ErrorAction Stop
                }
            }

            # Remove Edge tasks
            $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*edge*" }

            foreach ($task in $tasks) {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
            }

        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
        

    }

    UninstallEdge

    Function Removelnks {
        Write-Host "Removing Desktop shortcuts..." -NoNewline
        try {
            Get-ChildItem C:\users\Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
            Get-ChildItem $env:USERPROFILE\Desktop\*.lnk | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue } *>$null
            Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        }
        catch {
            Write-Host "[WARNING] $_" -ForegroundColor Red -BackgroundColor Black
        }
    }

    Removelnks
}

UnusedApps