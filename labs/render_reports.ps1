param([int[]]$Numbers=@(1,2,3,4))
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$reportFolder=Join-Path $root 'labs/reports'
$previewFolder=Join-Path $root 'tmp/labs/word-preview'
New-Item -ItemType Directory -Force -Path $previewFolder | Out-Null
$word=$null
$owned=$false
$document=$null
$results=@()
try {
    $word=New-Object -ComObject Word.Application
    if($word.Documents.Count -ne 0) {throw 'An existing Word session cannot be used for rendering'}
    $owned=$true
    $word.Visible=$false
    $word.DisplayAlerts=0
    foreach($number in $Numbers) {
        $files=@(Get-ChildItem -LiteralPath $reportFolder -Filter "ЛР_${number}_*.docx")
        if($files.Count -ne 1) {throw 'Expected one report per lab'}
        $source=$files[0]
        $destination=Join-Path $previewFolder ($source.BaseName+'.pdf')
        $document=$word.Documents.Open($source.FullName,$false,$true)
        $document.Repaginate()
        $document.Fields.Update() | Out-Null
        $document.ExportAsFixedFormat($destination,17)
        $results+=@{lab=$number;document=$source.Name;pages=$document.ComputeStatistics(2);pdf=$destination}
        $document.Close(0)
        [Runtime.InteropServices.Marshal]::ReleaseComObject($document) | Out-Null
        $document=$null
    }
    $results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $previewFolder 'render.json') -Encoding utf8
    $results | Select-Object lab,document,pages | ConvertTo-Json
} finally {
    if($document) {$document.Close(0);[Runtime.InteropServices.Marshal]::ReleaseComObject($document) | Out-Null}
    if($word) {
        if($owned -and $word.Documents.Count -eq 0) {$word.Quit(0)}
        [Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    }
}
