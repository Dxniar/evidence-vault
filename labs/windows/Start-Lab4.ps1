$ErrorActionPreference='Stop'
$scriptFile=Join-Path $PSScriptRoot 'Set-Lab4Policy.ps1'
$powershellFile=Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',([char]34+$scriptFile+[char]34),'-Mode','Apply')
try {
    $startedUtc=[DateTime]::UtcNow
    $process=Start-Process -FilePath $powershellFile -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments -PassThru -Wait
    $process.Refresh()
    $resultFile=Join-Path $PSScriptRoot '../results/lab4-windows.json'
    if(Test-Path -LiteralPath $resultFile) {
        $result=Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
        if($process.ExitCode -eq 0 -and (Get-Item -LiteralPath $resultFile).LastWriteTimeUtc -ge $startedUtc -and $result.completed -and $result.desired_settings_match) {
            Write-Host 'ЛР 4: параметры входа и пять категорий аудита применены и проверены.'
            Write-Host 'Полный результат: labs/results/lab4-windows.json'
            Write-Host 'Изменение экрана входа действует при следующем входе в Windows.'
        } else { Write-Host 'Проверка не завершена. Результат сохранён в labs/results/lab4-windows.json' }
    }
} catch { Write-Host 'Windows не предоставила права администратора. Настройки этим запуском не изменены.' }
Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null
