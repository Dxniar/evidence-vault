param(
    [string]$PolicyScript = (Join-Path $PSScriptRoot 'Set-Lab4Policy.ps1'),
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '../private/windows'),
    [string]$OutputPath
)
# Offline test: extracts Read-AuditBackup and the verification block through AST.
# Does not invoke auditpol, elevation, or registry writes. Replay output is kept
# in a new private fixture directory; real category evidence is never replaced.
$ErrorActionPreference = 'Stop'
$policyPath = [IO.Path]::GetFullPath($PolicyScript)
$backupRoot = [IO.Path]::GetFullPath($BackupDirectory)
$fixtureRoot = Join-Path $backupRoot ('parser-fixtures/'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
$parseTokens = $null
$parseErrors = $null
$policyAst = [Management.Automation.Language.Parser]::ParseFile($policyPath, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Policy script parse errors' }
$readerAst = $policyAst.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-AuditBackup'
}, $true)
if (-not $readerAst) { throw 'Read-AuditBackup was not found' }
. ([ScriptBlock]::Create($readerAst.Extent.Text))

$policyBytes = [IO.File]::ReadAllBytes($policyPath)
$systemLiterals = @($readerAst.FindAll({ param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $node.Value -notmatch '^[\x00-\x7F]*$'
}, $true) | ForEach-Object {
    @{ length=$_.Value.Length; codepoints=@($_.Value.ToCharArray() | ForEach-Object { [int]$_ }) }
})
$ansiCodePage = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name ACP).ACP
$encoding = [Text.Encoding]::GetEncoding($ansiCodePage)
function Read-ReferenceAudit([string]$Path) {
    $text = $encoding.GetString([IO.File]::ReadAllBytes($Path))
    $russianSystem = -join ([char[]]@(1057,1080,1089,1090,1077,1084,1072))
    $pattern = '^(?<machine>[^,]*),(?<target>[^,]*),(?<name>.*),(?<guid>\{[0-9a-fA-F-]{36}\}),(?<inclusion>[^,]*),(?<exclusion>[^,]*),(?<setting>[0-4])\s*$'
    @($text -split '\r?\n' | ForEach-Object {
        if ($_ -match $pattern -and $Matches.target -in @('System',$russianSystem)) {
            [pscustomobject]@{ guid=([guid]$Matches.guid).ToString('B'); name=$Matches.name; setting=[int]$Matches.setting }
        }
    })
}
$fileResults = @(Get-ChildItem -LiteralPath $backupRoot -Filter '*audit*.csv' -File | ForEach-Object {
    $file = $_
    $rows = @(Read-AuditBackup $file.FullName)
    $text = $encoding.GetString([IO.File]::ReadAllBytes($file.FullName))
    $legacyGuidRows = @($text | ConvertFrom-Csv -Header 'machine','target','subcategory','guid','inclusion','exclusion','setting' |
        Where-Object { $_.guid -match '^\{[0-9a-fA-F-]{36}\}$' })
    $referenceRows = @(Read-ReferenceAudit $file.FullName)
    $missingReferenceGuids = @($referenceRows.guid | Where-Object { $_ -notin $rows.guid })
    $valueMismatches = @(foreach ($referenceRow in $referenceRows) {
        $parsedRow = @($rows | Where-Object { $_.guid -eq $referenceRow.guid })
        if ($parsedRow.Count -ne 1 -or [int]$parsedRow[0].setting -ne $referenceRow.setting) { $referenceRow.guid }
    })
    if ($rows.Count -ne $referenceRows.Count -or $missingReferenceGuids.Count -or $valueMismatches.Count) {
        throw 'Policy reader lost or changed a native backup row'
    }
    $regexJoinWorks = $false
    if ($rows.Count) {
        $categoryGuid = '{69979849-797A-11D9-BED3-505054503030}'
        $subcategoryGuid = $rows[0].guid
        $fakeGetRows = @('Category,'+$categoryGuid, 'Machine,System,Subcategory,'+$subcategoryGuid+',Success and Failure,')
        $guids = @([regex]::Matches(($fakeGetRows -join "`n"), '\{[0-9a-fA-F-]{36}\}') |
            ForEach-Object { $_.Value } | Where-Object { $_ -ne $categoryGuid } | Select-Object -Unique)
        $matchedRows = @($rows | Where-Object { $_.guid -eq $guids[0] })
        $regexJoinWorks = ($guids.Count -eq 1 -and $matchedRows.Count -eq 1)
    }
    @{ file=$file.Name; legacy_fixed_column_rows=$legacyGuidRows.Count; reference_rows=$referenceRows.Count; reader_rows=$rows.Count;
       unique_guids=@($rows.guid | Sort-Object -Unique).Count; missing_guids=$missingReferenceGuids;
       comma_name_guids=@($referenceRows | Where-Object { $_.name.Contains(',') } | ForEach-Object { $_.guid });
       value_mismatches=$valueMismatches;
       invalid_flags=@($rows | Where-Object { $_.setting -notmatch '^[0-4]$' }).Count;
       regex_guid_join=$regexJoinWorks }
})
$header='machine,target,subcategory,guid,inclusion,exclusion,setting'
$commaRow='fixture,System,Name, with comma,{0CCE9228-69AE-11D9-BED3-505054503030},Success and Failure,,3'
$plainRow='fixture,System,Plain name,{0CCE9229-69AE-11D9-BED3-505054503030},No auditing,,0'
$fixtureCases=@(
    @{name='comma-name';content=($header+[Environment]::NewLine+$commaRow+[Environment]::NewLine+$plainRow);expected_rows=2;reject=$false},
    @{name='duplicate-guid';content=($header+[Environment]::NewLine+$commaRow+[Environment]::NewLine+$commaRow);expected_rows=0;reject=$true},
    @{name='malformed-system-row';content=($header+[Environment]::NewLine+'fixture,System,Missing GUID,Success,,3');expected_rows=0;reject=$true},
    @{name='invalid-flags';content=($header+[Environment]::NewLine+$commaRow.Replace(',,3',',,9'));expected_rows=0;reject=$true},
    @{name='empty-system-policy';content=$header;expected_rows=0;reject=$true}
)
$regressionResults=@(foreach ($fixtureCase in $fixtureCases) {
    $fixturePath=Join-Path $fixtureRoot ($fixtureCase.name+'.csv')
    [IO.File]::WriteAllText($fixturePath,$fixtureCase.content,$encoding)
    $rejected=$false
    $fixtureRows=@()
    try { $fixtureRows=@(Read-AuditBackup $fixturePath) } catch { $rejected=$true }
    $passed=($rejected -eq $fixtureCase.reject -and ($rejected -or $fixtureRows.Count -eq $fixtureCase.expected_rows))
    if (-not $passed) { throw ('Regression failed: '+$fixtureCase.name) }
    @{name=$fixtureCase.name;passed=$passed;rejected=$rejected;rows=$fixtureRows.Count}
})
$categoriesAst = $policyAst.Find({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$categories'
}, $true)
$verificationAst = $policyAst.Find({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$auditResult'
}, $true)
$mockVerification = @{ executed=$false }
if ($categoriesAst -and $verificationAst) {
    . ([ScriptBlock]::Create($categoriesAst.Extent.Text))
    $originalFile = Join-Path $backupRoot 'original-audit.csv'
    $observedAuditRows = @(Read-AuditBackup $originalFile)
    $mockRowsByCategory = @{}
    $mockIndex = 0
    foreach ($mockCategory in $categories) {
        $mockRow = if ($mockCategory.Guid -eq '{6997984B-797A-11D9-BED3-505054503030}') {
            @($observedAuditRows | Where-Object { $_.guid -eq '{0CCE9228-69AE-11D9-BED3-505054503030}' })[0]
        } else { $observedAuditRows[$mockIndex] }
        $mockRowsByCategory[$mockCategory.Guid] = @(
            'machine,target,subcategory,guid,inclusion,exclusion',
            ('fixture,System,category,'+$mockCategory.Guid+',Success and Failure,'),
            ('fixture,System,subcategory,'+$mockRow.guid+',Success and Failure,'),
            ('fixture,System,subcategory,'+([guid]$mockRow.guid).ToString('D')+',Success and Failure,')
        )
        $mockIndex++
    }
    function Invoke-AuditCommand([string[]]$Arguments) {
        if ($Arguments[0] -ne '/get') { throw 'Offline test prohibits native commands' }
        $mockGuid = $Arguments[1].Substring('/category:'.Length)
        if (-not $mockRowsByCategory.ContainsKey($mockGuid)) { throw 'Unexpected mock category' }
        return $mockRowsByCategory[$mockGuid]
    }
    $privateRoot = $fixtureRoot
    . ([ScriptBlock]::Create($verificationAst.Extent.Text))
    $mockVerification = @{ executed=$true; categories=$auditResult.Count;
        category_guid_excluded=(@($auditResult | Where-Object { $_.subcategories.guid -contains $_.guid }).Count -eq 0);
        repeated_guid_deduplicated=(@($auditResult | Where-Object { @($_.subcategories).Count -ne 1 }).Count -eq 0) }
}
$restoredComparison=@{available=$false}
$latestRestored=Get-ChildItem -LiteralPath $backupRoot -Filter 'restored-audit*.csv' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latestRestored) {
    $originalRows=@(Read-ReferenceAudit (Join-Path $backupRoot 'original-audit.csv'))
    $latestRestoredRows=@(Read-ReferenceAudit $latestRestored.FullName)
    $differences=@(foreach ($originalRow in $originalRows) {
        $restoredRow=@($latestRestoredRows | Where-Object { $_.guid -eq $originalRow.guid })
        if ($restoredRow.Count -ne 1 -or $restoredRow[0].setting -ne $originalRow.setting) {
            @{guid=$originalRow.guid;expected=$originalRow.setting;actual=if($restoredRow.Count){$restoredRow[0].setting}else{$null}}
        }
    })
    $restoredComparison=@{available=$true;file=$latestRestored.Name;original_rows=$originalRows.Count;
        restored_rows=$latestRestoredRows.Count;difference_count=$differences.Count;differences=$differences}
}
$result = @{ version=$PSVersionTable.PSVersion.ToString(); edition=$PSVersionTable.PSEdition;
    script_utf8_bom=($policyBytes.Length -ge 3 -and $policyBytes[0] -eq 239 -and $policyBytes[1] -eq 187 -and $policyBytes[2] -eq 191);
    ansi_code_page=$ansiCodePage; reader_non_ascii_literals=$systemLiterals; files=$fileResults;
    verification_block_mock=$mockVerification;
    parser_regressions=$regressionResults;latest_restored_comparison=$restoredComparison;
    fixture_directory=$fixtureRoot;policy_sha256=(Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash;
    host_mutations=$false }
$json = $result | ConvertTo-Json -Depth 8
if ($OutputPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $json, (New-Object Text.UTF8Encoding($true))) }
$json
