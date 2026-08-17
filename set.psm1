#requires -Version 5.1

if ($null -ne $ExecutionContext.SessionState.Module) {
    Set-StrictMode -Version 2.0

    # Preload read-only Windows management modules with WhatIf temporarily disabled.
    # Windows PowerShell 5.1 otherwise prints unrelated import-time alias previews.
    $moduleImportWhatIfPreference = $WhatIfPreference
    try {
        $WhatIfPreference = $false
        foreach ($dependencyModule in @('CimCmdlets', 'Appx', 'Dism')) {
            Import-Module $dependencyModule -ErrorAction Stop
        }
        Import-Module PrintManagement -ErrorAction SilentlyContinue
    }
    finally {
        $WhatIfPreference = $moduleImportWhatIfPreference
    }
}

$script:DefaultAppxNames = @(
    'Clipchamp.Clipchamp'
    'Microsoft.549981C3F5F10'
    'Microsoft.BingFinance'
    'Microsoft.BingFoodAndDrink'
    'Microsoft.BingHealthAndFitness'
    'Microsoft.BingNews'
    'Microsoft.BingSports'
    'Microsoft.BingTravel'
    'Microsoft.BingWeather'
    'Microsoft.GamingApp'
    'Microsoft.GetHelp'
    'Microsoft.Getstarted'
    'Microsoft.Microsoft3DViewer'
    'Microsoft.MicrosoftOfficeHub'
    'Microsoft.MicrosoftSolitaireCollection'
    'Microsoft.MixedReality.Portal'
    'Microsoft.OneConnect'
    'Microsoft.OutlookForWindows'
    'Microsoft.People'
    'Microsoft.PowerAutomateDesktop'
    'Microsoft.SkypeApp'
    'Microsoft.Todos'
    'Microsoft.Wallet'
    'Microsoft.WindowsAlarms'
    'Microsoft.WindowsFeedbackHub'
    'Microsoft.WindowsMaps'
    'Microsoft.WindowsSoundRecorder'
    'Microsoft.Xbox.TCUI'
    'Microsoft.XboxApp'
    'Microsoft.XboxGameOverlay'
    'Microsoft.XboxGamingOverlay'
    'Microsoft.XboxIdentityProvider'
    'Microsoft.XboxSpeechToTextOverlay'
    'Microsoft.ZuneMusic'
    'Microsoft.ZuneVideo'
    'MicrosoftCorporationII.QuickAssist'
    'microsoft.windowscommunicationsapps'
)

function Test-CleanMsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-CleanMsResult {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IList]$ResultList,

        [Parameter(Mandatory = $true)]
        [string]$Step,

        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Changed', 'Planned', 'Skipped', 'RestartRequired', 'Failed')]
        [string]$Status,

        [string]$Detail = ''
    )

    [void]$ResultList.Add([pscustomobject]@{
            Step   = $Step
            Target = $Target
            Status = $Status
            Detail = $Detail
        })
}

function Write-CleanMsStep {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "`n$Message" -ForegroundColor Cyan
}

function Test-CleanMsNameMatch {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowEmptyCollection()][string[]]$Pattern = @()
    )

    foreach ($candidate in $Pattern) {
        if ($Name -like $candidate) {
            return $true
        }
    }

    return $false
}

function Get-CleanMsPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Set-CleanMsRegistryDword {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][string]$Step,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Value,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    $target = "$Path\$Name"
    $currentValue = $null
    $currentValueKind = $null

    try {
        if (Test-Path -Path $Path) {
            $property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $property) {
                $currentValue = Get-CleanMsPropertyValue -InputObject $property -Name $Name
                try {
                    $registryKey = Get-Item -Path $Path -ErrorAction Stop
                    $currentValueKind = $registryKey.GetValueKind($Name)
                }
                catch {
                    # Unknown or wrong value kinds are rewritten as DWORD below.
                    $currentValueKind = $null
                }
            }
        }
    }
    catch {
        Write-Warning "Could not read $target. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $target -Status Failed -Detail $_.Exception.Message
        return 'Failed'
    }

    $currentDword = 0
    if ($currentValueKind -eq [Microsoft.Win32.RegistryValueKind]::DWord -and
        $null -ne $currentValue -and
        [int]::TryParse([string]$currentValue, [ref]$currentDword) -and
        $currentDword -eq $Value) {
        Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $target -Status Skipped -Detail 'Already configured.'
        return 'Unchanged'
    }

    if (-not $Context.ShouldProcess($target, "Set DWORD value to $Value")) {
        $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
        Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $target -Status $status
        return $(if ($DryRun) { 'Planned' } else { 'Declined' })
    }

    try {
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $target -Status Changed
        return 'Changed'
    }
    catch {
        Write-Warning "Could not configure $target. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $target -Status Failed -Detail $_.Exception.Message
        return 'Failed'
    }
}

function Remove-CleanMsAppxPackages {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][string]$Step,
        [Parameter(Mandatory = $true)][string[]]$Name,
        [string[]]$KeepName = @(),
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    $patterns = @($Name | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($patterns.Count -eq 0) {
        return
    }

    try {
        $matchedPackages = @(Get-AppxPackage -AllUsers -PackageTypeFilter Main, Bundle, Framework, Resource -ErrorAction Stop | Where-Object {
                (Test-CleanMsNameMatch -Name $_.Name -Pattern $patterns) -and
                -not (Test-CleanMsNameMatch -Name $_.Name -Pattern $KeepName)
            })

        $protectedNames = @($matchedPackages | Where-Object {
                $_.IsFramework -or $_.IsResourcePackage -or $_.NonRemovable
            } | Select-Object -ExpandProperty Name -Unique)
        $bundleNames = @($matchedPackages | Where-Object { $_.IsBundle } | Select-Object -ExpandProperty Name -Unique)
        $installedPackages = @($matchedPackages | Where-Object {
                $_.IsFramework -or $_.IsResourcePackage -or $_.NonRemovable -or
                $_.IsBundle -or $bundleNames -notcontains $_.Name
            })
    }
    catch {
        Write-Warning "Could not enumerate installed AppX packages. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step $Step -Target 'Installed AppX inventory' -Status Failed -Detail $_.Exception.Message
        return
    }

    foreach ($package in $installedPackages) {
        $isFramework = $package.PSObject.Properties.Name -contains 'IsFramework' -and $package.IsFramework
        $isResource = $package.PSObject.Properties.Name -contains 'IsResourcePackage' -and $package.IsResourcePackage
        $isNonRemovable = $package.PSObject.Properties.Name -contains 'NonRemovable' -and $package.NonRemovable

        if ($isFramework -or $isResource -or $isNonRemovable) {
            Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $package.PackageFullName -Status Skipped -Detail 'Framework, resource, or non-removable package.'
            continue
        }

        if (-not $Context.ShouldProcess($package.PackageFullName, 'Remove installed AppX package for all users')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $package.PackageFullName -Status $status
            continue
        }

        try {
            Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
            Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $package.PackageFullName -Status Changed -Detail 'Removed from existing user profiles.'
        }
        catch {
            Write-Warning "Could not remove AppX package $($package.Name). $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $package.PackageFullName -Status Failed -Detail $_.Exception.Message
        }
    }

    try {
        $provisionedPackages = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object {
                (Test-CleanMsNameMatch -Name $_.DisplayName -Pattern $patterns) -and
                -not (Test-CleanMsNameMatch -Name $_.DisplayName -Pattern $KeepName) -and
                $protectedNames -notcontains $_.DisplayName
            })
    }
    catch {
        Write-Warning "Could not enumerate provisioned AppX packages. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step $Step -Target 'Provisioned AppX inventory' -Status Failed -Detail $_.Exception.Message
        $provisionedPackages = @()
    }

    foreach ($package in $provisionedPackages) {
        if (-not $Context.ShouldProcess($package.PackageName, 'Remove AppX provisioning for current and future users')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $package.PackageName -Status $status
            continue
        }

        try {
            Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -AllUsers -ErrorAction Stop | Out-Null
            Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $package.PackageName -Status Changed -Detail 'Removed from the provisioning layer.'
        }
        catch {
            Write-Warning "Could not deprovision AppX package $($package.DisplayName). $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step $Step -Target $package.PackageName -Status Failed -Detail $_.Exception.Message
        }
    }
}

function Remove-CleanMsOptionalFeatures {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    Write-CleanMsStep 'Removing optional Windows features and printers...'
    $step = 'Optional features'
    $featureNames = @(
        'WindowsMediaPlayer'
        'WorkFolders-Client'
        'Printing-XPSServices-Features'
        'FaxServicesClientPackage'
    )

    try {
        $features = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not enumerate optional Windows features. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Windows optional feature inventory' -Status Failed -Detail $_.Exception.Message
        $features = @()
    }

    foreach ($featureName in $featureNames) {
        $feature = $features | Where-Object { $_.FeatureName -eq $featureName } | Select-Object -First 1
        if ($null -eq $feature -or $feature.State -eq 'Disabled' -or $feature.State -eq 'DisabledWithPayloadRemoved') {
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $featureName -Status Skipped -Detail 'Not present or already disabled.'
            continue
        }

        if (-not $Context.ShouldProcess($featureName, 'Disable Windows optional feature')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $featureName -Status $status
            continue
        }

        try {
            $result = Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $featureName -Status Changed -Detail "RestartNeeded=$($result.RestartNeeded)"
        }
        catch {
            Write-Warning "Could not disable optional feature $featureName. $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $featureName -Status Failed -Detail $_.Exception.Message
        }
    }

    $capabilityPatterns = @('Media.WindowsMediaPlayer*', 'Print.Fax.Scan*')
    try {
        $capabilities = @(Get-WindowsCapability -Online -ErrorAction Stop | Where-Object {
                $_.State -eq 'Installed' -and (Test-CleanMsNameMatch -Name $_.Name -Pattern $capabilityPatterns)
            })
    }
    catch {
        Write-Warning "Could not enumerate Windows capabilities. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Windows capability inventory' -Status Failed -Detail $_.Exception.Message
        $capabilities = @()
    }

    foreach ($capability in $capabilities) {
        if (-not $Context.ShouldProcess($capability.Name, 'Remove Windows capability')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $capability.Name -Status $status
            continue
        }

        try {
            $result = Remove-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $capability.Name -Status Changed -Detail "RestartNeeded=$($result.RestartNeeded)"
        }
        catch {
            Write-Warning "Could not remove capability $($capability.Name). $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $capability.Name -Status Failed -Detail $_.Exception.Message
        }
    }

    if ($null -eq (Get-Command Get-Printer -ErrorAction SilentlyContinue)) {
        Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Fax and XPS printer queues' -Status Skipped -Detail 'PrintManagement cmdlets are unavailable.'
        return
    }

    try {
        $printers = @(Get-Printer -ErrorAction Stop | Where-Object {
                $_.Name -eq 'Fax' -or
                $_.Name -eq 'Microsoft XPS Document Writer' -or
                $_.DriverName -like '*Microsoft*XPS*' -or
                $_.DriverName -like '*Shared Fax*'
            })
    }
    catch {
        Write-Warning "Could not enumerate printers. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Printer inventory' -Status Failed -Detail $_.Exception.Message
        $printers = @()
    }

    foreach ($printer in $printers) {
        if (-not $Context.ShouldProcess($printer.Name, 'Remove printer queue')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $printer.Name -Status $status
            continue
        }

        try {
            Remove-Printer -Name $printer.Name -ErrorAction Stop
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $printer.Name -Status Changed
        }
        catch {
            Write-Warning "Could not remove printer $($printer.Name). $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $printer.Name -Status Failed -Detail $_.Exception.Message
        }
    }
}

function Set-CleanMsPrivacyPolicies {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    Write-CleanMsStep 'Configuring documented Microsoft Edge and Office privacy policies...'

    $edgePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    $edgeValues = [ordered]@{
        DiagnosticData                    = 0
        UrlDiagnosticDataEnabled          = 0
        Edge3PSerpTelemetryEnabled         = 0
        PersonalizationReportingEnabled   = 0
        UserFeedbackAllowed               = 0
        PaymentMethodQueryEnabled          = 0
        AutofillCreditCardEnabled          = 0
        AutofillAddressEnabled             = 0
        SearchSuggestEnabled               = 0
        EdgeShoppingAssistantEnabled       = 0
        ConfigureDoNotTrack                = 1
        HubsSidebarEnabled                 = 0
        Microsoft365CopilotChatIconEnabled = 0
        EdgeEntraCopilotPageContext        = 0
    }

    foreach ($entry in $edgeValues.GetEnumerator()) {
        $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Edge privacy' -Path $edgePath -Name $entry.Key -Value $entry.Value -DryRun $DryRun
    }

    $officeTelemetryPath = 'HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry'
    $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Office privacy' -Path $officeTelemetryPath -Name 'SendTelemetry' -Value 3 -DryRun $DryRun
}

function Set-CleanMsWindowsSyncPolicy {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    Write-CleanMsStep 'Disabling Windows settings synchronization...'
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
    $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Windows sync' -Path $path -Name 'DisableSettingSync' -Value 2 -DryRun $DryRun
    $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Windows sync' -Path $path -Name 'DisableSettingSyncUserOverride' -Value 1 -DryRun $DryRun
}

function Set-CleanMsWidgetsPolicy {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($null -eq $os) {
        Add-CleanMsResult -ResultList $ResultList -Step 'Widgets' -Target 'Windows version' -Status Failed -Detail 'Could not determine the Windows build.'
        return
    }

    if ([int]$os.BuildNumber -ge 22000) {
        Write-CleanMsStep 'Disabling Windows 11 Widgets by policy...'
        $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Widgets' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name 'AllowNewsAndInterests' -Value 0 -DryRun $DryRun
    }
    else {
        Write-CleanMsStep 'Disabling Windows 10 News and interests by policy...'
        $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'News and interests' -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -Value 0 -DryRun $DryRun
    }
}

function Disable-CleanMsCopilot {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [string[]]$KeepName = @(),
        [switch]$SkipAppRemoval,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    Write-CleanMsStep 'Applying the supported Copilot cleanup and compatibility policy...'
    if (-not $SkipAppRemoval) {
        Remove-CleanMsAppxPackages -Context $Context -ResultList $ResultList -Step 'Copilot app' -Name @('Microsoft.Copilot') -KeepName $KeepName -DryRun $DryRun
    }

    $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Copilot legacy policy' -Path 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -Value 1 -DryRun $DryRun
}

function Get-CleanMsUninstallEntries {
    $registryRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($root in $registryRoots) {
        if (-not (Test-Path -Path $root)) {
            continue
        }

        foreach ($key in Get-ChildItem -Path $root -ErrorAction SilentlyContinue) {
            $entry = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $entry) {
                continue
            }

            $displayName = Get-CleanMsPropertyValue -InputObject $entry -Name 'DisplayName'
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                continue
            }

            [pscustomobject]@{
                DisplayName          = $displayName
                DisplayVersion       = Get-CleanMsPropertyValue -InputObject $entry -Name 'DisplayVersion'
                UninstallString      = Get-CleanMsPropertyValue -InputObject $entry -Name 'UninstallString'
                QuietUninstallString = Get-CleanMsPropertyValue -InputObject $entry -Name 'QuietUninstallString'
                NoRemove             = Get-CleanMsPropertyValue -InputObject $entry -Name 'NoRemove'
                SystemComponent      = Get-CleanMsPropertyValue -InputObject $entry -Name 'SystemComponent'
                ProductCode          = $key.PSChildName
                RegistryPath         = $key.PSPath
            }
        }
    }
}

function Split-CleanMsCommandLine {
    param([Parameter(Mandatory = $true)][string]$CommandLine)

    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded -match '^\s*"([^"]+\.exe)"\s*(.*)$') {
        return [pscustomobject]@{ FilePath = $matches[1].Trim(); Arguments = $matches[2].Trim() }
    }

    if ($expanded -match '^\s*(.+?\.exe)\s*(.*)$') {
        return [pscustomobject]@{ FilePath = $matches[1].Trim(); Arguments = $matches[2].Trim() }
    }

    throw "Could not parse uninstall command: $CommandLine"
}

function Assert-CleanMsMicrosoftSignature {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath -ErrorAction Stop
    $subject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }
    if ($signature.Status -ne 'Valid' -or $subject -notmatch '(?i)(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Executable does not have a valid Microsoft signature: $LiteralPath"
    }
}

function Invoke-CleanMsUninstallCommand {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [string]$ExpectedFileName,
        [string[]]$AllowedRootPath = @(),
        [switch]$RequireMicrosoftSignature
    )

    $command = Split-CleanMsCommandLine -CommandLine $CommandLine
    if (-not [IO.Path]::IsPathRooted($command.FilePath)) {
        throw "Uninstaller must use an absolute path: $($command.FilePath)"
    }

    $command.FilePath = [IO.Path]::GetFullPath($command.FilePath)
    if ($AllowedRootPath.Count -gt 0) {
        $isAllowedPath = $false
        foreach ($rootPath in $AllowedRootPath) {
            if ([string]::IsNullOrWhiteSpace($rootPath)) {
                continue
            }

            $normalizedRoot = [IO.Path]::GetFullPath($rootPath).TrimEnd('\') + '\'
            if ($command.FilePath.StartsWith($normalizedRoot, [StringComparison]::OrdinalIgnoreCase)) {
                $isAllowedPath = $true
                break
            }
        }

        if (-not $isAllowedPath) {
            throw "Uninstaller is outside the trusted Windows or Program Files roots: $($command.FilePath)"
        }
    }

    if (-not (Test-Path -LiteralPath $command.FilePath -PathType Leaf)) {
        throw "Uninstaller executable was not found: $($command.FilePath)"
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedFileName) -and [IO.Path]::GetFileName($command.FilePath) -ne $ExpectedFileName) {
        throw "Unexpected uninstaller executable: $($command.FilePath)"
    }

    if ($RequireMicrosoftSignature) {
        Assert-CleanMsMicrosoftSignature -LiteralPath $command.FilePath
    }

    $startParameters = @{
        FilePath    = $command.FilePath
        Wait        = $true
        PassThru    = $true
        WindowStyle = 'Hidden'
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($command.Arguments)) {
        $startParameters['ArgumentList'] = $command.Arguments
    }

    $process = Start-Process @startParameters
    if ($process.ExitCode -notin @(0, 1605, 1614, 3010)) {
        throw "$DisplayName uninstaller exited with code $($process.ExitCode)."
    }

    return $process.ExitCode
}

function Remove-CleanMsTeams {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [string[]]$KeepName = @(),
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    Write-CleanMsStep 'Removing Microsoft Teams and the Teams Meeting Add-in...'
    Remove-CleanMsAppxPackages -Context $Context -ResultList $ResultList -Step 'Teams app' -Name @('MSTeams', 'MicrosoftTeams') -KeepName $KeepName -DryRun $DryRun

    $entries = @(Get-CleanMsUninstallEntries | Where-Object {
            $_.DisplayName -like '*Teams Meeting Add-in*' -or
            $_.DisplayName -like '*Teams Meeting Addin*'
        })

    foreach ($entry in $entries) {
        $target = "$($entry.DisplayName) $($entry.DisplayVersion)".Trim()
        if ($entry.ProductCode -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
            Add-CleanMsResult -ResultList $ResultList -Step 'Teams add-in' -Target $target -Status Skipped -Detail 'Only machine-wide MSI product-code entries are trusted for elevated removal.'
            continue
        }

        if (-not $Context.ShouldProcess($target, 'Uninstall Teams Meeting Add-in')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step 'Teams add-in' -Target $target -Status $status
            continue
        }

        try {
            $systemDirectory = [Environment]::SystemDirectory
            $msiExecPath = Join-Path $systemDirectory 'msiexec.exe'
            $msiCommand = '"{0}" /x {1} /qn /norestart' -f $msiExecPath, $entry.ProductCode
            $exitCode = Invoke-CleanMsUninstallCommand -CommandLine $msiCommand -DisplayName $entry.DisplayName -ExpectedFileName 'msiexec.exe' -AllowedRootPath @($systemDirectory) -RequireMicrosoftSignature

            Add-CleanMsResult -ResultList $ResultList -Step 'Teams add-in' -Target $target -Status Changed -Detail "ExitCode=$exitCode"
        }
        catch {
            Write-Warning "Could not uninstall $target. $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step 'Teams add-in' -Target $target -Status Failed -Detail $_.Exception.Message
        }
    }
}

function Remove-CleanMsOneDrive {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    Write-CleanMsStep 'Uninstalling Microsoft OneDrive without deleting OneDrive folder contents...'
    $step = 'OneDrive'
    $systemDirectory = [Environment]::SystemDirectory
    $windowsDirectory = [IO.Directory]::GetParent($systemDirectory).FullName
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $entries = @(Get-CleanMsUninstallEntries | Where-Object { $_.DisplayName -eq 'Microsoft OneDrive' })
    $uninstallCommands = New-Object System.Collections.ArrayList

    foreach ($entry in $entries) {
        if (-not [string]::IsNullOrWhiteSpace($entry.QuietUninstallString)) {
            [void]$uninstallCommands.Add($entry.QuietUninstallString)
        }
        if (-not [string]::IsNullOrWhiteSpace($entry.UninstallString)) {
            [void]$uninstallCommands.Add($entry.UninstallString)
        }
    }

    $installMarkers = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
        [void]$installMarkers.Add((Join-Path $localAppData 'Microsoft\OneDrive\OneDrive.exe'))
    }
    foreach ($basePath in @($programFiles, $programFilesX86)) {
        if (-not [string]::IsNullOrWhiteSpace($basePath)) {
            [void]$installMarkers.Add((Join-Path $basePath 'Microsoft OneDrive\OneDrive.exe'))
        }
    }

    $hasInstallMarker = @($installMarkers | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -gt 0
    $hasRunningProcess = $null -ne (Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Select-Object -First 1)
    $installationDetected = $entries.Count -gt 0 -or $hasInstallMarker -or $hasRunningProcess

    if ($installationDetected) {
        $trustedOneDriveRoots = @($windowsDirectory, $programFiles, $programFilesX86) | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }
        foreach ($programFilesRoot in @($programFiles, $programFilesX86)) {
            if ([string]::IsNullOrWhiteSpace($programFilesRoot)) {
                continue
            }

            $oneDriveMachineRoot = Join-Path $programFilesRoot 'Microsoft OneDrive'
            foreach ($machineSetup in Get-ChildItem -Path $oneDriveMachineRoot -Filter OneDriveSetup.exe -File -Recurse -ErrorAction SilentlyContinue) {
                [void]$uninstallCommands.Add(('"{0}" /allusers /uninstall' -f $machineSetup.FullName))
            }
        }

        foreach ($setupPath in @(
                (Join-Path $systemDirectory 'OneDriveSetup.exe')
                (Join-Path $windowsDirectory 'SysWOW64\OneDriveSetup.exe')
            )) {
            if (Test-Path -LiteralPath $setupPath -PathType Leaf) {
                [void]$uninstallCommands.Add(('"{0}" /uninstall' -f $setupPath))
            }
        }

        $uninstallCommands = @($uninstallCommands | Select-Object -Unique)
        if ($uninstallCommands.Count -eq 0) {
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft OneDrive' -Status Failed -Detail 'OneDrive appears installed, but no trusted uninstaller was found.'
        }
        elseif ($Context.ShouldProcess('Microsoft OneDrive', 'Stop the sync client and run a Microsoft-signed OneDriveSetup.exe uninstaller')) {
            try {
                Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
                $attemptErrors = New-Object System.Collections.ArrayList
                $exitCode = $null
                foreach ($uninstallCommand in $uninstallCommands) {
                    try {
                        $exitCode = Invoke-CleanMsUninstallCommand -CommandLine $uninstallCommand -DisplayName 'Microsoft OneDrive' -ExpectedFileName 'OneDriveSetup.exe' -AllowedRootPath $trustedOneDriveRoots -RequireMicrosoftSignature
                        break
                    }
                    catch {
                        [void]$attemptErrors.Add($_.Exception.Message)
                    }
                }

                if ($null -eq $exitCode) {
                    throw ($attemptErrors -join ' | ')
                }

                Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft OneDrive' -Status Changed -Detail "ExitCode=$exitCode; OneDrive folder contents were not explicitly deleted."
            }
            catch {
                Write-Warning "Could not uninstall Microsoft OneDrive. $($_.Exception.Message)"
                Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft OneDrive' -Status Failed -Detail $_.Exception.Message
            }
        }
        else {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft OneDrive' -Status $status -Detail 'The script will not explicitly delete OneDrive folder contents.'
        }
    }
    else {
        Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft OneDrive' -Status Skipped -Detail 'No installed OneDrive client was detected.'
    }

    $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step $step -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1 -DryRun $DryRun

    $shortcutPaths = @(
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'OneDrive.lnk')
        (Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\OneDrive.lnk')
    )

    foreach ($shortcut in $shortcutPaths) {
        if (-not (Test-Path -LiteralPath $shortcut)) {
            continue
        }

        if (-not $Context.ShouldProcess($shortcut, 'Remove OneDrive shortcut')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $shortcut -Status $status
            continue
        }

        try {
            Remove-Item -LiteralPath $shortcut -Force -ErrorAction Stop
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $shortcut -Status Changed
        }
        catch {
            Write-Warning "Could not remove shortcut $shortcut. $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target $shortcut -Status Failed -Detail $_.Exception.Message
        }
    }
}

function Get-CleanMsProcessEnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    return [Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::Process)
}

function Invoke-CleanMsWithGlobalMutex {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $mutex = $null
    $acquired = $false
    try {
        $mutex = New-Object Threading.Mutex($false, $Name)
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
            throw 'A previous deep Edge-removal process ended unexpectedly. Inspect WINDIR, Geo, and recovery backups before retrying.'
        }

        if (-not $acquired) {
            throw 'Another deep Edge-removal process is already running.'
        }

        return & $Action
    }
    finally {
        if ($acquired -and $null -ne $mutex) {
            try {
                $mutex.ReleaseMutex()
            }
            catch {
                Write-Warning "Could not release the deep Edge-removal mutex. $($_.Exception.Message)"
            }
        }
        if ($null -ne $mutex) {
            $mutex.Dispose()
        }
    }
}

function Set-CleanMsProcessEnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )

    [Environment]::SetEnvironmentVariable($Name, $Value, [EnvironmentVariableTarget]::Process)
}

function Invoke-CleanMsWithTemporaryRegistryValues {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$ValueEntry,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $registryKey = Get-Item -Path $Path -ErrorAction Stop
    $originalValues = New-Object System.Collections.ArrayList
    try {
        $existingNames = @($registryKey.GetValueNames())
        foreach ($entry in $ValueEntry) {
            $existed = $existingNames -contains $entry.Name
            $originalValue = $null
            $originalKind = $null
            if ($existed) {
                $originalValue = $registryKey.GetValue(
                    $entry.Name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $originalKind = $registryKey.GetValueKind($entry.Name)
            }

            [void]$originalValues.Add([pscustomobject]@{
                    Name    = $entry.Name
                    Existed = $existed
                    Value   = $originalValue
                    Kind    = $originalKind
                })
        }

        try {
            foreach ($entry in $ValueEntry) {
                $registryKey.SetValue($entry.Name, $entry.Value, $entry.Kind)
            }

            return & $Action
        }
        finally {
            $restoreErrors = New-Object System.Collections.ArrayList
            foreach ($original in $originalValues) {
                try {
                    if ($original.Existed) {
                        $registryKey.SetValue($original.Name, $original.Value, $original.Kind)
                    }
                    else {
                        $registryKey.DeleteValue($original.Name, $false)
                    }
                }
                catch {
                    [void]$restoreErrors.Add("$($original.Name): $($_.Exception.Message)")
                }
            }

            if ($restoreErrors.Count -gt 0) {
                $rollbackException = [System.InvalidOperationException]::new("Could not restore temporary registry values at $Path. $($restoreErrors -join ' | ')")
                $rollbackException.Data['CleanMsRollbackFailure'] = $true
                throw $rollbackException
            }
        }
    }
    finally {
        if ($null -ne $registryKey) {
            $registryKey.Close()
        }
    }
}

function Invoke-CleanMsEdgeWithTemporaryWindir {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)

    $environmentPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $originalProcessWindir = Get-CleanMsProcessEnvironmentValue -Name 'windir'
    try {
        Set-CleanMsProcessEnvironmentValue -Name 'windir' -Value ''
        return Invoke-CleanMsWithTemporaryRegistryValues -Path $environmentPath -ValueEntry @(
            [pscustomobject]@{
                Name  = 'windir'
                Value = ''
                Kind  = [Microsoft.Win32.RegistryValueKind]::ExpandString
            }
        ) -Action $Action
    }
    finally {
        try {
            Set-CleanMsProcessEnvironmentValue -Name 'windir' -Value $originalProcessWindir
        }
        catch {
            $rollbackException = [System.InvalidOperationException]::new("Could not restore the process WINDIR value. $($_.Exception.Message)")
            $rollbackException.Data['CleanMsRollbackFailure'] = $true
            throw $rollbackException
        }
    }
}

function Invoke-CleanMsEdgeWithTemporaryEuRegion {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)

    return Invoke-CleanMsWithTemporaryRegistryValues -Path 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International\Geo' -ValueEntry @(
        [pscustomobject]@{
            Name  = 'Name'
            Value = 'FR'
            Kind  = [Microsoft.Win32.RegistryValueKind]::String
        }
        [pscustomobject]@{
            Name  = 'Nation'
            Value = '84'
            Kind  = [Microsoft.Win32.RegistryValueKind]::String
        }
    ) -Action $Action
}

function Invoke-CleanMsEdgeWithTemporaryAllowUninstall {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)

    $edgeUpdateDevPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev'
    $keyExisted = Test-Path -Path $edgeUpdateDevPath
    if (-not $keyExisted) {
        New-Item -Path $edgeUpdateDevPath -Force -ErrorAction Stop | Out-Null
    }

    try {
        return Invoke-CleanMsWithTemporaryRegistryValues -Path $edgeUpdateDevPath -ValueEntry @(
            [pscustomobject]@{
                Name  = 'AllowUninstall'
                Value = ''
                Kind  = [Microsoft.Win32.RegistryValueKind]::String
            }
        ) -Action $Action
    }
    finally {
        if (-not $keyExisted -and (Test-Path -Path $edgeUpdateDevPath)) {
            try {
                $createdKey = Get-Item -Path $edgeUpdateDevPath -ErrorAction Stop
                try {
                    $isEmpty = @($createdKey.GetValueNames()).Count -eq 0 -and @($createdKey.GetSubKeyNames()).Count -eq 0
                }
                finally {
                    $createdKey.Close()
                }

                if ($isEmpty) {
                    Remove-Item -Path $edgeUpdateDevPath -Force -ErrorAction Stop
                }
            }
            catch {
                $rollbackException = [System.InvalidOperationException]::new("Could not restore the temporary EdgeUpdateDev key. $($_.Exception.Message)")
                $rollbackException.Data['CleanMsRollbackFailure'] = $true
                throw $rollbackException
            }
        }
    }
}

function Read-CleanMsFileBytes {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    return ,([IO.File]::ReadAllBytes($LiteralPath))
}

function Write-CleanMsFileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    [IO.File]::WriteAllBytes($LiteralPath, $Bytes)
}

function Invoke-CleanMsEdgeWithTemporaryRegionPolicy {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)

    $windowsDirectory = [IO.Directory]::GetParent([Environment]::SystemDirectory).FullName
    $policyPaths = @(
        @(
            (Join-Path ([Environment]::SystemDirectory) 'IntegratedServicesRegionPolicySet.json')
            (Join-Path $windowsDirectory 'SysWOW64\IntegratedServicesRegionPolicySet.json')
        ) | Select-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    )
    if ($policyPaths.Count -eq 0) {
        throw 'IntegratedServicesRegionPolicySet.json was not found in System32 or SysWOW64.'
    }

    $policyGuid = '{1bca278a-5d11-4acf-ad2f-f9ab6d7f93a6}'
    $transactions = New-Object System.Collections.ArrayList
    foreach ($policyPath in $policyPaths) {
        $originalBytes = Read-CleanMsFileBytes -LiteralPath $policyPath
        $jsonText = [Text.Encoding]::UTF8.GetString($originalBytes)
        if ($jsonText.Length -gt 0 -and $jsonText[0] -eq [char]0xFEFF) {
            $jsonText = $jsonText.Substring(1)
        }
        $integratedServices = $jsonText | ConvertFrom-Json -ErrorAction Stop
        $edgePolicies = @($integratedServices.policies | Where-Object {
                $guidProperty = $_.PSObject.Properties['guid']
                $null -ne $guidProperty -and [string]$guidProperty.Value -eq $policyGuid
            })
        if ($edgePolicies.Count -ne 1) {
            throw "Expected exactly one Edge uninstall policy $policyGuid in $policyPath; found $($edgePolicies.Count)."
        }

        $stateProperty = $edgePolicies[0].PSObject.Properties['defaultState']
        if ($null -eq $stateProperty) {
            $edgePolicies[0] | Add-Member -MemberType NoteProperty -Name 'defaultState' -Value 'enabled'
        }
        else {
            $stateProperty.Value = 'enabled'
        }

        $modifiedJson = $integratedServices | ConvertTo-Json -Depth 100
        $modifiedBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($modifiedJson)
        $originalAcl = Get-Acl -LiteralPath $policyPath -ErrorAction Stop
        [void]$transactions.Add([pscustomobject]@{
                Path          = $policyPath
                OriginalBytes = $originalBytes
                ModifiedBytes = $modifiedBytes
                OriginalSddl  = $originalAcl.Sddl
                BackupPath    = ('{0}.clean-ms-products.{1}.bak' -f $policyPath, [Guid]::NewGuid().ToString('N'))
                BackupCreated = $false
                AclChanged    = $false
                ContentChanged = $false
            })
    }

    $cleanupErrors = New-Object System.Collections.ArrayList

    try {
        foreach ($transaction in $transactions) {
            Copy-Item -LiteralPath $transaction.Path -Destination $transaction.BackupPath -Force -ErrorAction Stop
            $transaction.BackupCreated = $true
            $backupBytes = Read-CleanMsFileBytes -LiteralPath $transaction.BackupPath
            if ([Convert]::ToBase64String($backupBytes) -ne [Convert]::ToBase64String($transaction.OriginalBytes)) {
                throw "The recovery backup did not match the original file: $($transaction.BackupPath)"
            }
        }

        $administratorSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $administrator = $administratorSid.Translate([Security.Principal.NTAccount])
        foreach ($transaction in $transactions) {
            $temporaryAcl = Get-Acl -LiteralPath $transaction.Path -ErrorAction Stop
            $temporaryAcl.SetOwner($administrator)
            $temporaryRule = New-Object Security.AccessControl.FileSystemAccessRule($administrator, 'FullControl', 'Allow')
            [void]$temporaryAcl.AddAccessRule($temporaryRule)
            $transaction.AclChanged = $true
            Set-Acl -LiteralPath $transaction.Path -AclObject $temporaryAcl -ErrorAction Stop

            $transaction.ContentChanged = $true
            Write-CleanMsFileBytes -LiteralPath $transaction.Path -Bytes $transaction.ModifiedBytes
        }
        return & $Action
    }
    finally {
        foreach ($transaction in @($transactions)[($transactions.Count - 1)..0]) {
            if ($transaction.ContentChanged) {
                try {
                    Write-CleanMsFileBytes -LiteralPath $transaction.Path -Bytes $transaction.OriginalBytes
                }
                catch {
                    [void]$cleanupErrors.Add("$($transaction.Path) content restore failed: $($_.Exception.Message)")
                }
            }

            if ($transaction.AclChanged) {
                try {
                    $restoreAcl = New-Object Security.AccessControl.FileSecurity
                    $restoreAcl.SetSecurityDescriptorSddlForm($transaction.OriginalSddl)
                    Set-Acl -LiteralPath $transaction.Path -AclObject $restoreAcl -ErrorAction Stop
                }
                catch {
                    [void]$cleanupErrors.Add("$($transaction.Path) ACL restore failed: $($_.Exception.Message)")
                }
            }
        }

        if ($cleanupErrors.Count -eq 0) {
            foreach ($transaction in $transactions) {
                if ($transaction.BackupCreated) {
                    try {
                        Remove-Item -LiteralPath $transaction.BackupPath -Force -ErrorAction Stop
                    }
                    catch {
                        [void]$cleanupErrors.Add("$($transaction.BackupPath) cleanup failed: $($_.Exception.Message)")
                    }
                }
            }
        }

        if ($cleanupErrors.Count -gt 0) {
            $backupPaths = @($transactions | Where-Object { $_.BackupCreated } | Select-Object -ExpandProperty BackupPath)
            $rollbackException = [System.InvalidOperationException]::new("Could not fully restore IntegratedServicesRegionPolicySet.json. Recovery backups: $($backupPaths -join ', '). $($cleanupErrors -join ' | ')")
            $rollbackException.Data['CleanMsRollbackFailure'] = $true
            throw $rollbackException
        }
    }
}

function Remove-CleanMsEdgeScheduledTasks {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
                $taskName = [string](Get-CleanMsPropertyValue -InputObject $_ -Name 'TaskName')
                $taskPath = [string](Get-CleanMsPropertyValue -InputObject $_ -Name 'TaskPath')
                $nameAllowed = $taskName -match '(?i)^MicrosoftEdgeUpdateTaskMachine(?:Core|UA)(?:\{[0-9a-f-]{36}\})?$' -or
                    $taskName -match '(?i)^MicrosoftEdgeUpdateBrowserReplacementTask$'
                $pathAllowed = $taskPath -eq '\' -or $taskPath -eq '\Microsoft\EdgeUpdate\'
                $nameAllowed -and $pathAllowed
            })
    }
    catch {
        Write-Warning "Could not enumerate Edge scheduled tasks. $($_.Exception.Message)"
        Add-CleanMsResult -ResultList $ResultList -Step 'Edge scheduled tasks' -Target 'Task Scheduler' -Status Failed -Detail $_.Exception.Message
        return
    }

    foreach ($task in $tasks) {
        $taskName = [string](Get-CleanMsPropertyValue -InputObject $task -Name 'TaskName')
        $taskPath = [string](Get-CleanMsPropertyValue -InputObject $task -Name 'TaskPath')
        if ([string]::IsNullOrWhiteSpace($taskName)) {
            continue
        }

        $target = "$taskPath$taskName"
        if (-not $Context.ShouldProcess($target, 'Unregister Edge scheduled task')) {
            $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
            $detail = if ($DryRun) { 'Conditional on confirmed Edge browser removal.' } else { '' }
            Add-CleanMsResult -ResultList $ResultList -Step 'Edge scheduled tasks' -Target $target -Status $status -Detail $detail
            continue
        }

        try {
            $unregisterParameters = @{
                TaskName    = $taskName
                Confirm     = $false
                ErrorAction = 'Stop'
            }
            if (-not [string]::IsNullOrWhiteSpace($taskPath)) {
                $unregisterParameters['TaskPath'] = $taskPath
            }
            Unregister-ScheduledTask @unregisterParameters
            Add-CleanMsResult -ResultList $ResultList -Step 'Edge scheduled tasks' -Target $target -Status Changed
        }
        catch {
            Write-Warning "Could not unregister Edge scheduled task $target. $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step 'Edge scheduled tasks' -Target $target -Status Failed -Detail $_.Exception.Message
        }
    }
}

function Remove-CleanMsEdge {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IList]$ResultList,
        [Parameter(Mandatory = $true)][bool]$DryRun
    )

    Write-CleanMsStep 'Attempting unsupported force-removal of the Microsoft Edge browser...'
    $step = 'Edge removal'
    $programFilesRoots = @(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    $installerCandidates = New-Object System.Collections.ArrayList
    $detectedBrowserPaths = New-Object System.Collections.ArrayList

    foreach ($programFilesRoot in $programFilesRoots) {
        $applicationRoot = Join-Path $programFilesRoot 'Microsoft\Edge\Application'
        $rootBrowserPath = Join-Path $applicationRoot 'msedge.exe'
        $rootBrowserExists = Test-Path -LiteralPath $rootBrowserPath -PathType Leaf
        if ($rootBrowserExists) {
            [void]$detectedBrowserPaths.Add($rootBrowserPath)
        }

        foreach ($versionDirectory in Get-ChildItem -Path $applicationRoot -Directory -ErrorAction SilentlyContinue) {
            $versionBrowserPath = Join-Path $versionDirectory.FullName 'msedge.exe'
            $setupPath = Join-Path $versionDirectory.FullName 'Installer\setup.exe'
            $browserPath = if ($rootBrowserExists) {
                $rootBrowserPath
            }
            elseif (Test-Path -LiteralPath $versionBrowserPath -PathType Leaf) {
                $versionBrowserPath
            }
            else {
                $null
            }

            if ($null -eq $browserPath) {
                continue
            }
            if ($detectedBrowserPaths -notcontains $browserPath) {
                [void]$detectedBrowserPaths.Add($browserPath)
            }
            if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
                continue
            }

            [version]$parsedVersion = [version]'0.0'
            [void][version]::TryParse($versionDirectory.Name, [ref]$parsedVersion)
            [void]$installerCandidates.Add([pscustomobject]@{
                    Version     = $parsedVersion
                    BrowserPath = $browserPath
                    SetupPath   = $setupPath
                })
        }
    }

    $installer = $installerCandidates | Sort-Object -Property @{ Expression = { $_.Version }; Descending = $true } | Select-Object -First 1
    $installerTrustError = $null
    if ($null -ne $installer) {
        try {
            Assert-CleanMsMicrosoftSignature -LiteralPath $installer.SetupPath
        }
        catch {
            $installerTrustError = $_.Exception.Message
        }
    }

    if ($null -eq $installer) {
        if ($detectedBrowserPaths.Count -gt 0) {
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft Edge' -Status Failed -Detail 'The machine-wide Edge browser exists, but no trusted Edge setup.exe was found. WebView2 was not considered a target.'
        }
        else {
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft Edge' -Status Skipped -Detail 'No machine-wide Edge browser was detected. WebView2 was not considered an Edge browser target.'
        }
    }
    elseif ($null -ne $installerTrustError) {
        Add-CleanMsResult -ResultList $ResultList -Step $step -Target $installer.SetupPath -Status Failed -Detail "Deep removal was not attempted because setup.exe trust verification failed. $installerTrustError"
    }
    elseif (-not $Context.ShouldProcess($installer.BrowserPath, 'Run the signed Edge setup with AllowUninstall, WINDIR, EU-region, and protected-policy force-removal fallbacks')) {
        $status = if ($DryRun) { 'Planned' } else { 'Skipped' }
        Add-CleanMsResult -ResultList $ResultList -Step $step -Target $installer.BrowserPath -Status $status -Detail 'Unsupported force-uninstall with temporary EdgeUpdateDev AllowUninstall, WINDIR, FR/84 region, and System32/SysWOW64 IntegratedServicesRegionPolicySet.json/ACL fallbacks.'
        if ($DryRun) {
            Remove-CleanMsEdgeScheduledTasks -Context $Context -ResultList $ResultList -DryRun $true
        }
    }
    else {
        try {
            Invoke-CleanMsWithGlobalMutex -Name 'Global\CleanMsProductsEdgeRemoval' -Action {
        $uninstallCommand = '"{0}" --uninstall --msedge --system-level --verbose-logging --force-uninstall' -f $installer.SetupPath
        $attemptNames = @(
            'direct signed setup'
            'temporary EdgeUpdateDev AllowUninstall'
            'temporary machine/process WINDIR'
            'temporary default-user FR/84 region'
            'temporary System32/SysWOW64 IntegratedServicesRegionPolicySet.json and ACL'
        )
        $attemptErrors = New-Object System.Collections.ArrayList
        $successfulAttempt = $null
        $restartRequested = $false
        $fatalRollbackError = $null
        $fatalTrustError = $null
        $remainingBrowserPaths = @($detectedBrowserPaths | Where-Object {
                Test-Path -LiteralPath $_ -PathType Leaf
            })

        foreach ($attemptName in $attemptNames) {
            if ($remainingBrowserPaths.Count -eq 0 -or $restartRequested) {
                break
            }

            try {
                if (-not (Test-Path -LiteralPath $installer.SetupPath -PathType Leaf)) {
                    throw "Edge setup.exe disappeared before $attemptName."
                }
                Assert-CleanMsMicrosoftSignature -LiteralPath $installer.SetupPath
            }
            catch {
                $fatalTrustError = $_.Exception.Message
                [void]$attemptErrors.Add("$attemptName trust check: $fatalTrustError")
                break
            }

            try {
                Stop-Process -Name msedge -Force -ErrorAction SilentlyContinue
                $invokeInstaller = {
                    Invoke-CleanMsUninstallCommand -CommandLine $uninstallCommand -DisplayName 'Microsoft Edge' -ExpectedFileName 'setup.exe' -AllowedRootPath $programFilesRoots -RequireMicrosoftSignature
                }

                switch ($attemptName) {
                    'direct signed setup' {
                        $exitCode = & $invokeInstaller
                    }
                    'temporary EdgeUpdateDev AllowUninstall' {
                        $exitCode = Invoke-CleanMsEdgeWithTemporaryAllowUninstall -Action $invokeInstaller
                    }
                    'temporary machine/process WINDIR' {
                        $exitCode = Invoke-CleanMsEdgeWithTemporaryWindir -Action $invokeInstaller
                    }
                    'temporary default-user FR/84 region' {
                        $exitCode = Invoke-CleanMsEdgeWithTemporaryEuRegion -Action $invokeInstaller
                    }
                    'temporary System32/SysWOW64 IntegratedServicesRegionPolicySet.json and ACL' {
                        $exitCode = Invoke-CleanMsEdgeWithTemporaryRegionPolicy -Action $invokeInstaller
                    }
                }

                if ($exitCode -eq 3010) {
                    $restartRequested = $true
                }
            }
            catch {
                [void]$attemptErrors.Add("$attemptName`: $($_.Exception.Message)")
                if ($_.Exception.Data.Contains('CleanMsRollbackFailure')) {
                    $fatalRollbackError = $_.Exception.Message
                }
            }

            $remainingBrowserPaths = @($detectedBrowserPaths | Where-Object {
                    Test-Path -LiteralPath $_ -PathType Leaf
                })
            if ($remainingBrowserPaths.Count -eq 0 -and $null -eq $fatalRollbackError) {
                $successfulAttempt = $attemptName
            }
            if ($null -ne $fatalRollbackError) {
                break
            }
        }

        if ($null -ne $fatalRollbackError) {
            Write-Warning "Microsoft Edge removal changed temporary system state that could not be fully restored. $fatalRollbackError"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft Edge rollback' -Status Failed -Detail $fatalRollbackError
        }
        elseif ($null -ne $fatalTrustError) {
            Write-Warning "Microsoft Edge setup trust changed during removal. $fatalTrustError"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft Edge setup trust' -Status Failed -Detail $fatalTrustError
        }
        elseif ($remainingBrowserPaths.Count -eq 0) {
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft Edge' -Status Changed -Detail "The Edge browser was removed with: $successfulAttempt. Temporary AllowUninstall/WINDIR/region/file/ACL state was restored."
            Remove-CleanMsEdgeScheduledTasks -Context $Context -ResultList $ResultList -DryRun $DryRun
        }
        elseif ($restartRequested) {
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft Edge' -Status RestartRequired -Detail "The forced uninstaller requested a restart; Edge files remain at: $($remainingBrowserPaths -join ', ')."
        }
        else {
            $detail = "Edge files remain at: $($remainingBrowserPaths -join ', ')."
            if ($attemptErrors.Count -gt 0) {
                $detail += " Attempts: $($attemptErrors -join ' | ')"
            }
            Write-Warning "Could not force-remove Microsoft Edge. $detail"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Microsoft Edge' -Status Failed -Detail $detail
        }
            } | Out-Null
        }
        catch {
            Write-Warning "Could not start the serialized Edge removal sequence. $($_.Exception.Message)"
            Add-CleanMsResult -ResultList $ResultList -Step $step -Target 'Edge deep-removal lock' -Status Failed -Detail $_.Exception.Message
        }
    }

    # These documented Edge Update values are also written as a best-effort reinstall block.
    # Microsoft only guarantees policy enforcement on the editions and join states in its policy documentation.
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
    $appGuid = '{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}'
    $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Edge reinstall prevention' -Path $policyPath -Name "Install$appGuid" -Value 0 -DryRun $DryRun
    $null = Set-CleanMsRegistryDword -Context $Context -ResultList $ResultList -Step 'Edge reinstall prevention' -Path $policyPath -Name "Uninstall$appGuid" -Value 1 -DryRun $DryRun
}

function Invoke-CleanMsProducts {
    <#
    .SYNOPSIS
        Removes selected optional Microsoft apps and configures privacy-focused policies.

    .DESCRIPTION
        Uses AppX/DISM and documented policy interfaces. The default Edge step deliberately
        goes beyond supported interfaces: it invokes the force-uninstall switch of the signed
        Edge setup and, while Edge remains installed, retries with temporary EdgeUpdateDev
        AllowUninstall, WINDIR, FR/84 default-region, and System32/SysWOW64
        IntegratedServicesRegionPolicySet.json/ACL overrides. Those values, bytes, and ACLs
        are restored in finally blocks. After confirmed browser removal it
        unregisters allowlisted Edge Update tasks. SkipEdge disables the entire Edge sequence.
        The command does not explicitly delete OneDrive folder contents.

    .PARAMETER KeepApp
        AppX package names or wildcard patterns to preserve.

    .PARAMETER AdditionalApp
        Additional exact AppX package names to remove. Wildcards are rejected before changes.

    .PARAMETER RemoveTeams
        Also removes new/consumer Teams packages and dynamically discovered Teams Meeting Add-ins.

    .PARAMETER SkipEdge
        Skips the force-uninstall attempt, deep-removal fallbacks, Edge Update task cleanup,
        and Edge reinstall-prevention policy values.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [string[]]$KeepApp = @(),
        [string[]]$AdditionalApp = @(),
        [switch]$RemoveTeams,
        [switch]$SkipApps,
        [switch]$SkipOptionalFeatures,
        [switch]$SkipPrivacy,
        [switch]$SkipWindowsSync,
        [switch]$SkipWidgets,
        [switch]$SkipCopilot,
        [switch]$SkipOneDrive,
        [switch]$SkipEdge,
        [switch]$PassThru
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'Clean MS Products supports Windows only.'
    }

    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'Clean MS Products requires 64-bit Windows. No changes were made.'
    }

    if (-not [Environment]::Is64BitProcess) {
        throw 'Run the 64-bit Windows PowerShell executable. No changes were made.'
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        throw "Could not determine the Windows version. No changes were made. $($_.Exception.Message)"
    }

    $build = [int]$os.BuildNumber
    if ([int]$os.ProductType -ne 1 -or -not ($build -eq 19045 -or $build -ge 22631)) {
        throw 'This release supports Windows 10 22H2 client (build 19045) and Windows 11 23H2 or later clients only. No changes were made.'
    }

    if (-not (Test-CleanMsAdministrator)) {
        throw 'Run Windows PowerShell as an administrator before invoking this command.'
    }

    $wildcardAdditionalApps = @($AdditionalApp | Where-Object {
            [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($_)
        })
    if ($wildcardAdditionalApps.Count -gt 0) {
        throw "AdditionalApp accepts exact AppX package names only. Wildcards were rejected before any changes: $($wildcardAdditionalApps -join ', ')"
    }

    $dryRun = [bool]$WhatIfPreference
    $results = New-Object System.Collections.ArrayList
    Write-Host "Clean MS Products on $($os.Caption) (build $($os.BuildNumber))" -ForegroundColor Green

    if (-not $SkipApps) {
        Write-CleanMsStep 'Removing selected AppX packages for existing and future users...'
        $appNames = @($script:DefaultAppxNames) + @($AdditionalApp)
        Remove-CleanMsAppxPackages -Context $PSCmdlet -ResultList $results -Step 'AppX apps' -Name $appNames -KeepName $KeepApp -DryRun $dryRun
    }

    if (-not $SkipOptionalFeatures) {
        Remove-CleanMsOptionalFeatures -Context $PSCmdlet -ResultList $results -DryRun $dryRun
    }

    if (-not $SkipPrivacy) {
        Set-CleanMsPrivacyPolicies -Context $PSCmdlet -ResultList $results -DryRun $dryRun
    }

    if (-not $SkipWindowsSync) {
        Set-CleanMsWindowsSyncPolicy -Context $PSCmdlet -ResultList $results -DryRun $dryRun
    }

    if (-not $SkipWidgets) {
        Set-CleanMsWidgetsPolicy -Context $PSCmdlet -ResultList $results -DryRun $dryRun
    }

    if (-not $SkipCopilot) {
        Disable-CleanMsCopilot -Context $PSCmdlet -ResultList $results -KeepName $KeepApp -SkipAppRemoval:$SkipApps -DryRun $dryRun
    }

    if (-not $SkipOneDrive) {
        Remove-CleanMsOneDrive -Context $PSCmdlet -ResultList $results -DryRun $dryRun
    }

    if ($RemoveTeams) {
        Remove-CleanMsTeams -Context $PSCmdlet -ResultList $results -KeepName $KeepApp -DryRun $dryRun
    }

    if (-not $SkipEdge) {
        Remove-CleanMsEdge -Context $PSCmdlet -ResultList $results -DryRun $dryRun
    }

    $changed = @($results | Where-Object { $_.Status -eq 'Changed' }).Count
    $planned = @($results | Where-Object { $_.Status -eq 'Planned' }).Count
    $skipped = @($results | Where-Object { $_.Status -eq 'Skipped' }).Count
    $restartRequired = @($results | Where-Object { $_.Status -eq 'RestartRequired' }).Count
    $failed = @($results | Where-Object { $_.Status -eq 'Failed' }).Count

    Write-Host "`nSummary: changed=$changed, planned=$planned, skipped=$skipped, restart-required=$restartRequired, failed=$failed" -ForegroundColor $(if ($failed -gt 0 -or $restartRequired -gt 0) { 'Yellow' } else { 'Green' })
    if ($failed -gt 0) {
        Write-Warning 'One or more operations failed. Use -PassThru to inspect the itemized results.'
    }

    if ($PassThru) {
        return $results
    }

    return [pscustomobject]@{
        Changed = $changed
        Planned = $planned
        Skipped = $skipped
        RestartRequired = $restartRequired
        Failed  = $failed
    }
}

Set-Alias -Name UnusedApps -Value Invoke-CleanMsProducts

if ($null -ne $ExecutionContext.SessionState.Module) {
    Export-ModuleMember -Function Invoke-CleanMsProducts -Alias UnusedApps
}
else {
    Invoke-CleanMsProducts
}
