param(
    [ValidateSet('Apply','Inspect','Restore')][string]$Mode = 'Inspect'
)
$ErrorActionPreference = 'Stop'
$scriptVersion = '2026-10-13.6'
$scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$privateRoot = Join-Path $projectRoot 'labs/private/windows'
$resultRoot = Join-Path $projectRoot 'labs/results'
$backupPath = Join-Path $privateRoot 'original-state.json'
$auditBackup = Join-Path $privateRoot 'original-audit.csv'
$resultPath = Join-Path $resultRoot 'lab4-windows.json'
$systemPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$winlogonPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$lsaPolicy = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$settings = @(
    @{Path=$systemPolicy;Name='legalnoticecaption';Kind='String';Value='ПРЕДУПРЕЖДЕНИЕ'},
    @{Path=$systemPolicy;Name='legalnoticetext';Kind='String';Value='На этом компьютере могут работать только зарегистрированные пользователи!'},
    @{Path=$systemPolicy;Name='DisableCAD';Kind='DWord';Value=0},
    @{Path=$systemPolicy;Name='DontDisplayLastUserName';Kind='DWord';Value=1},
    @{Path=$winlogonPolicy;Name='PasswordExpiryWarning';Kind='DWord';Value=7},
    @{Path=$lsaPolicy;Name='SCENoApplyLegacyAuditPolicy';Kind='DWord';Value=1}
)
$categories = @(
    @{Name='Проверка учётных данных';Guid='{69979850-797A-11D9-BED3-505054503030}'},
    @{Name='Вход и выход';Guid='{69979849-797A-11D9-BED3-505054503030}'},
    @{Name='Изменение политики';Guid='{6997984D-797A-11D9-BED3-505054503030}'},
    @{Name='Использование привилегий';Guid='{6997984B-797A-11D9-BED3-505054503030}'},
    @{Name='Управление учётными записями';Guid='{6997984E-797A-11D9-BED3-505054503030}'}
)
New-Item -ItemType Directory -Path $privateRoot,$resultRoot -Force | Out-Null
$administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $administrator) {
    @{completed=$false;mode=$Mode;error='AdministratorRequired';changed=$false;script_version=$scriptVersion;script_sha256=$scriptHash;verified_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    throw 'Run this script from an elevated PowerShell session.'
}

function Invoke-AuditCommand([string[]]$Arguments) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & "$env:WINDIR/System32/auditpol.exe" @Arguments 2>&1
        $nativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($nativeExit -ne 0) {
        $output | Out-String | Set-Content -LiteralPath (Join-Path $privateRoot 'auditpol-failure.txt') -Encoding UTF8
        throw "Auditpol failed with code $nativeExit"
    }
    return $output
}

function Get-RegistrySnapshot($entry) {
    $key = Get-Item -LiteralPath $entry.Path
    $exists = $key.GetValueNames() -contains $entry.Name
    @{Path=$entry.Path;Name=$entry.Name;Exists=$exists;Kind=if($exists){$key.GetValueKind($entry.Name).ToString()}else{$null};Value=if($exists){$key.GetValue($entry.Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}else{$null}}
}

function Get-OriginalState {
    $state = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
    if (@($state.registry).Count -ne $settings.Count) { throw 'Invalid original state' }
    if ((Get-FileHash -LiteralPath $auditBackup -Algorithm SHA256).Hash -ne $state.audit_sha256) { throw 'Audit backup hash mismatch' }
    Read-AuditBackup $auditBackup | Out-Null
    $seen = @{}
    foreach ($original in $state.registry) {
        if (-not ($settings | Where-Object { $_.Path -eq $original.Path -and $_.Name -eq $original.Name })) { throw 'Unexpected registry target in backup' }
        $identity = $original.Path + '|' + $original.Name
        if ($seen.ContainsKey($identity)) { throw 'Duplicate registry target in backup' }
        $seen[$identity]=$true
        if ($original.Exists -and $original.Kind -notin @('String','DWord')) { throw 'Unexpected registry value kind' }
    }
    return $state
}

function Read-AuditBackup([string]$Path) {
    $ansiCodePage = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name ACP).ACP
    $csvEncoding = [Text.Encoding]::GetEncoding($ansiCodePage)
    $csvText = $csvEncoding.GetString([IO.File]::ReadAllBytes($Path))
    # Auditpol can emit unquoted commas inside a localized subcategory name.
    # Anchor the fields on the GUID and numeric flags instead of CSV positions.
    $policyRows = @()
    $rowPattern = '^(?<machine>[^,]*),(?<target>System|Система),(?<subcategory>.*),(?<guid>\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}),(?<inclusion>[^,]*),(?<exclusion>[^,]*),(?<setting>[0-4])\s*$'
    foreach ($line in ($csvText -split '\r?\n')) {
        if ($line -notmatch '^[^,]*,(System|Система),') { continue }
        $rowMatch = [regex]::Match($line,$rowPattern)
        if (-not $rowMatch.Success) { throw 'Malformed system audit row in backup' }
        $policyRows += [pscustomobject]@{
            machine=$rowMatch.Groups['machine'].Value
            target=$rowMatch.Groups['target'].Value
            subcategory=$rowMatch.Groups['subcategory'].Value
            guid=([guid]$rowMatch.Groups['guid'].Value).ToString('B')
            inclusion=$rowMatch.Groups['inclusion'].Value
            exclusion=$rowMatch.Groups['exclusion'].Value
            setting=$rowMatch.Groups['setting'].Value
        }
    }
    if ($policyRows.Count -eq 0 -or @($policyRows.guid | Select-Object -Unique).Count -ne $policyRows.Count) {
        throw 'Missing or duplicate system audit rows in backup'
    }
    return $policyRows
}

function Restore-OriginalState {
    $state = Get-OriginalState
    $restoreErrors = @()
    foreach ($original in $state.registry) {
        $registryKey = $null
        try {
            $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($original.Path.Substring(6),$true)
            if ($original.Exists) {
                $savedValue = if ($original.Kind -eq 'DWord') { [int]$original.Value } else { [string]$original.Value }
                $registryKey.SetValue($original.Name,$savedValue,[Microsoft.Win32.RegistryValueKind]::$($original.Kind))
            } else { $registryKey.DeleteValue($original.Name,$false) }
        } catch { $restoreErrors += $_.Exception.GetType().Name }
        finally { if($registryKey) { $registryKey.Close() } }
    }
    try { Invoke-AuditCommand -Arguments @('/restore',"/file:$auditBackup") | Out-Null }
    catch {
        # If CSV restore fails, restore the hash-checked snapshot through GUIDs
        # and verify every row instead of treating the command as sufficient.
        try {
            $originalAuditRows = @(Read-AuditBackup $auditBackup)
            if ($originalAuditRows.Count -eq 0) { throw 'Audit backup contains no system policy' }
            foreach ($policyRow in $originalAuditRows) {
                $flags=[int]$policyRow.setting
                if ($flags -notin @(0,1,2,3,4)) { throw 'Invalid audit flags in backup' }
                $successOption=if($flags -band 1){'/success:enable'}else{'/success:disable'}
                $failureOption=if($flags -band 2){'/failure:enable'}else{'/failure:disable'}
                Invoke-AuditCommand -Arguments @('/set',"/subcategory:$($policyRow.guid)",$successOption,$failureOption) | Out-Null
            }
        } catch { $restoreErrors += $_.Exception.GetType().Name }
    }
    foreach ($original in $state.registry) {
        $actual = Get-RegistrySnapshot $original
        if ($actual.Exists -ne $original.Exists -or ($original.Exists -and ($actual.Kind -ne $original.Kind -or $actual.Value -cne $original.Value))) { $restoreErrors += 'RegistryVerificationFailed' }
    }
    try {
        $restoredAuditPath = Join-Path $privateRoot ('restored-audit-'+[Guid]::NewGuid().ToString('N')+'.csv')
        Invoke-AuditCommand -Arguments @('/backup',"/file:$restoredAuditPath") | Out-Null
        $expectedAudit = @(Read-AuditBackup $auditBackup)
        $actualAudit = @(Read-AuditBackup $restoredAuditPath)
        if ($expectedAudit.Count -eq 0 -or $actualAudit.Count -ne $expectedAudit.Count) { throw 'Audit verification row count mismatch' }
        foreach ($expected in $expectedAudit) {
            $actual = @($actualAudit | Where-Object { $_.guid -eq $expected.guid })
            if ($actual.Count -ne 1 -or $actual[0].setting -ne $expected.setting) { throw 'Audit verification mismatch' }
        }
    } catch { $restoreErrors += $_.Exception.GetType().Name }
    if ($restoreErrors.Count) {
        $restoreErrors | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $privateRoot 'restore-errors.json') -Encoding UTF8
        throw 'Original state could not be fully verified'
    }
}

$changed = $false
try {
    if ($Mode -eq 'Apply') {
        if (-not (Test-Path -LiteralPath $backupPath)) {
            $originalRegistry = @($settings | ForEach-Object { Get-RegistrySnapshot $_ })
            Invoke-AuditCommand -Arguments @('/backup',"/file:$auditBackup") | Out-Null
            @{created_utc=[DateTime]::UtcNow.ToString('o');registry=$originalRegistry;audit_sha256=(Get-FileHash -LiteralPath $auditBackup -Algorithm SHA256).Hash} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $backupPath -Encoding UTF8
        }
        Get-OriginalState | Out-Null
        $changed = $true
        foreach ($setting in $settings) {
            New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -PropertyType $setting.Kind -Value $setting.Value -Force | Out-Null
        }
        foreach ($category in $categories) {
            Invoke-AuditCommand -Arguments @('/set',"/category:$($category.Guid)",'/success:enable','/failure:enable') | Out-Null
        }
    } elseif ($Mode -eq 'Restore') {
        Restore-OriginalState
        $changed = $true
    }
    $registryResult = @($settings | ForEach-Object {
        $observed = Get-RegistrySnapshot $_
        @{name=$_.Name;value=$observed.Value;expected=$_.Value;matches=($observed.Exists -and $observed.Kind -eq $_.Kind -and $observed.Value -ceq $_.Value)}
    })
    $observedAuditPath = Join-Path $privateRoot ('observed-audit-'+[Guid]::NewGuid().ToString('N')+'.csv')
    Invoke-AuditCommand -Arguments @('/backup',"/file:$observedAuditPath") | Out-Null
    $observedAuditRows = @(Read-AuditBackup $observedAuditPath)
    $auditResult = @($categories | ForEach-Object {
        $category = $_
        $lines = Invoke-AuditCommand -Arguments @('/get',"/category:$($category.Guid)",'/r')
        $lines | Out-String | Set-Content -LiteralPath (Join-Path $privateRoot ('category-'+$category.Guid.Trim('{}')+'.txt')) -Encoding UTF8
        $subcategoryGuids = @([regex]::Matches(($lines -join "`n"),'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') | ForEach-Object { ([guid]$_.Value).ToString('B') } | Where-Object { $_ -ne $category.Guid } | Select-Object -Unique)
        $subcategories = @($subcategoryGuids | ForEach-Object {
            $subcategoryGuid = $_
            $savedRow = @($observedAuditRows | Where-Object { $_.guid -eq $subcategoryGuid })
            if ($savedRow.Count -ne 1) {
                @{script_version=$scriptVersion;script_sha256=$scriptHash;guid=$subcategoryGuid;rows=$observedAuditRows.Count;culture=[Globalization.CultureInfo]::CurrentCulture.Name;guids=@($observedAuditRows.guid)} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $privateRoot 'audit-match-diagnostic.json') -Encoding UTF8
                throw 'Missing or ambiguous effective audit setting'
            }
            $settingValue = [int]$savedRow[0].setting
            @{name=$savedRow[0].subcategory;guid=$subcategoryGuid;setting=$settingValue;success_and_failure=($settingValue -eq 3)}
        })
        @{name=$category.Name;guid=$category.Guid;success_and_failure=($subcategories.Count -gt 0 -and @($subcategories | Where-Object { -not $_.success_and_failure }).Count -eq 0);subcategories=$subcategories}
    })
    $os = Get-CimInstance Win32_OperatingSystem
    $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $log = Get-WinEvent -ListLog Security
    $saferPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    $srp = if (Test-Path -LiteralPath $saferPath) { Get-ItemProperty -LiteralPath $saferPath } else { $null }
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4719} -MaxEvents 3 -ErrorAction SilentlyContinue)
    if ($events.Count -lt 3) { $events = @(Get-WinEvent -LogName Security -MaxEvents 3) }
    '<Events>' + ($events | ForEach-Object { $_.ToXml() }) + '</Events>' | Set-Content -LiteralPath (Join-Path $privateRoot 'security-events.xml') -Encoding UTF8
    $safeEvents = @($events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        @{id=$_.Id;record_id=$_.RecordId;time_utc=$_.TimeCreated.ToUniversalTime().ToString('o');provider=$_.ProviderName;level=$_.LevelDisplayName;data=@($xml.Event.EventData.Data | ForEach-Object {
            $value = $_.'#text'
            if ($_.Name -match 'User|Domain|Sid|Account|Machine|Address|ProcessName|Workstation') { $value='[скрыто в учебном отчёте]' }
            @{name=$_.Name;value=$value}
        })}
    })
    $matches = @($registryResult | Where-Object { -not $_.matches }).Count -eq 0 -and @($auditResult | Where-Object { -not $_.success_and_failure }).Count -eq 0
    if($Mode -eq 'Apply' -and -not $matches) { throw 'Desired policy verification failed' }
    $result = @{completed=$true;mode=$Mode;changed=$changed;verified_utc=[DateTime]::UtcNow.ToString('o');desired_settings_match=$matches;os=@{caption=$os.Caption;version=$os.Version;build=$os.BuildNumber;edition=$version.EditionID};registry=$registryResult;audit=$auditResult;security_log=@{path=$log.LogFilePath;maximum_size_bytes=$log.MaximumSizeInBytes;mode=$log.LogMode.ToString();enabled=$log.IsEnabled;record_count=$log.RecordCount};events=$safeEvents;secpol_available=(Test-Path "$env:WINDIR/System32/secpol.msc");software_restriction_policy=@{default_level=if($srp){$srp.DefaultLevel}else{$null};enforcement_not_verified=$true};interactive_logon_effect_observed=$false}
    $result.script_version=$scriptVersion
    $result.script_sha256=$scriptHash
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultPath -Encoding UTF8
} catch {
    $failure = $_.Exception.GetType().Name
    try {
        ($_ | Out-String) + $_.ScriptStackTrace | Set-Content -LiteralPath (Join-Path $privateRoot 'failure-detail.txt') -Encoding UTF8
    } catch { }
    $restored = $false
    if ($Mode -eq 'Apply' -and $changed -and (Test-Path -LiteralPath $backupPath)) {
        try { Restore-OriginalState; $restored=$true } catch {
            try {
                ($_ | Out-String) + $_.ScriptStackTrace | Set-Content -LiteralPath (Join-Path $privateRoot 'restore-failure-detail.txt') -Encoding UTF8
            } catch { }
        }
    }
    @{completed=$false;mode=$Mode;error=$failure;changed=$changed;original_state_restored=$restored;script_version=$scriptVersion;script_sha256=$scriptHash} | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
