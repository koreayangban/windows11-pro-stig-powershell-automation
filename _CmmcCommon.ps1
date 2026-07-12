# _CmmcCommon.ps1는 다른 스크립트에서 호출하여 사용됩니다.
# Windows 11, PowerShell 5.1, 이 파일은 단독 실행 용도가 아닙니다.
# 조치(-mode enforce) 전 백업만 backup\ 폴더에 파일로 남깁니다.

function Get-CmmcTimestamp { param([switch]$ForFile)
    if ($ForFile) { return (Get-Date).ToString('yyyyMMdd_HHmmss') }
    return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

function Test-CmmcAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-CmmcMode {
    param([string]$Mode)
    if (-not $Mode) { return 'Check' }
    switch -regex ($Mode.Trim().ToLower()) {
        '^(c|check)$'   { return 'Check' }
        '^(e|enforce)$' { return 'Enforce' }
        default         { return $null }
    }
}

function Show-CmmcUsage {
    param([Parameter(Mandatory)]$Meta)
    $name = $Meta.Name
    Write-Host ''
    Write-Host ("USAGE: .\{0}.ps1 [-Mode <Check|Enforce>] [-Quiet] [-Help]" -f $name) -ForegroundColor Cyan
    Write-Host ''
    Write-Host ("  Script : {0}" -f $name)
    if ($Meta.Purpose) { Write-Host ("  Purpose: {0}" -f $Meta.Purpose) }
    if ($Meta.Modes)   { Write-Host ("  Modes  : {0}" -f $Meta.Modes) }
    if ($Meta.Scope)   { Write-Host ("  Scope  : {0}" -f $Meta.Scope) }
    Write-Host '  Common parameters:'
    Write-Host '    -Mode <Check|Enforce>   Default Check (read-only). Case-insensitive; abbrev c/e allowed.'
    Write-Host '    -Quiet                  Suppress operational INFO logs; show results + summary only'
    Write-Host '    -Help                   Show this usage and exit. Aliases: -Usage, -h'
    if ($Meta.Params)   { Write-Host ("  Script-specific: {0}" -f $Meta.Params) }
    if ($Meta.Examples) { Write-Host '  Examples:'; foreach ($e in $Meta.Examples) { Write-Host ("    {0}" -f $e) } }
    Write-Host ''
}

function Initialize-CmmcRun {
    param(
        [Parameter(Mandatory)][string]$ScriptId,
        [ValidateSet('Check','Enforce')][string]$Mode = 'Check',
        [switch]$Quiet
    )
    $stamp = Get-CmmcTimestamp -ForFile
    $base  = "{0}_{1}_{2}" -f $ScriptId, $Mode, $stamp
    $backupDir = Join-Path $PSScriptRoot 'backup'
    $ctx = [pscustomobject]@{
        ScriptId  = $ScriptId
        Mode      = $Mode
        Host      = $env:COMPUTERNAME
        User      = $env:USERNAME
        Started   = Get-CmmcTimestamp
        BackupDir = $backupDir
        BackupFile= Join-Path $backupDir ($base + '.backup.json')
        Results   = New-Object System.Collections.ArrayList
        Backups   = New-Object System.Collections.ArrayList
        Quiet     = [bool]$Quiet
    }
    Write-CmmcLog -Context $ctx -Message ("=== {0} [{1}] start · Host={2} User={3} ===" -f $ScriptId,$Mode,$ctx.Host,$ctx.User) -Level INFO
    if ($Mode -eq 'Enforce' -and -not (Test-CmmcAdmin)) {
        Write-CmmcLog -Context $ctx -Message 'Enforce mode requires administrator privileges. Re-run from an elevated PowerShell.' -Level WARN
    }
    return $ctx
}

function Write-CmmcLog {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','PASS','FAIL','ENFORCE')][string]$Level = 'INFO',
        [switch]$Always
    )
    $line = "[{0}] [{1}] {2}" -f (Get-CmmcTimestamp), $Level, $Message

    $quiet = ($Context -and $Context.PSObject.Properties['Quiet'] -and $Context.Quiet)
    $suppressConsole = ($quiet -and $Level -eq 'INFO' -and -not $Always)
    if (-not $suppressConsole) {
        switch ($Level) {
            'FAIL'    { Write-Host $line -ForegroundColor Red }
            'ERROR'   { Write-Host $line -ForegroundColor Red }
            'WARN'    { Write-Host $line -ForegroundColor Yellow }
            'PASS'    { Write-Host $line -ForegroundColor Green }
            'ENFORCE' { Write-Host $line -ForegroundColor Cyan }
            default   { Write-Host $line }
        }
    }
}

function Add-CmmcResult {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Item,
        [string]$Control = '',
        [string]$Expected = '',
        [string]$Actual = '',
        [ValidateSet('PASS','FAIL','N/A','NA','INFO','ENFORCED','ERROR')][string]$Status = 'INFO',
        [string]$Detail = '',

        [string]$StigId = '',
        [string]$Severity = '',
        [string]$Cci = '',
        [string]$Deviation = ''
    )
    if ($Status -eq 'NA') { $Status = 'N/A' }

    $row = [pscustomobject]@{
        Timestamp    = Get-CmmcTimestamp
        Script       = $Context.ScriptId
        Mode         = $Context.Mode
        STIG_ID      = $StigId
        Severity     = $Severity
        CCI          = $Cci
        CMMC_Control = $Control
        Item         = $Item
        Expected     = $Expected
        Actual       = $Actual
        Result       = $Status
        Deviation    = $Deviation
        Note         = $Detail
        Host         = $Context.Host
    }
    [void]$Context.Results.Add($row)
    $lvl = switch ($Status) { 'PASS' {'PASS'} 'FAIL' {'FAIL'} 'ENFORCED' {'ENFORCE'} 'ERROR' {'ERROR'} default {'INFO'} }
    if ($StigId) {

        $sevTok = if ($Severity) { $Severity } else { '[확인필요]' }
        $ctlTok = if ($Control)  { $Control }  else { '[확인필요]' }
        $cciTok = if ($Cci)      { $Cci }      else { '[확인필요]' }
        $msg = "{0} [{1}] · {2} · {3} | {4} | expected='{5}' actual='{6}'" -f $StigId,$sevTok,$ctlTok,$cciTok,$Item,$Expected,$Actual
        if ($Deviation) { $msg = "{0} | {1}" -f $msg,$Deviation }
    } else {

        $msg = "{0} | {1} | expected='{2}' actual='{3}' | {4}" -f $Control,$Item,$Expected,$Actual,$Status
    }

    Write-CmmcLog -Context $Context -Message $msg -Level $lvl -Always:($Status -ne 'INFO')
}

function Backup-CmmcRegistry {
    param([Parameter(Mandatory)]$Context,[Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Name)
    $existed = $false; $value = $null; $type = $null
    try {
        if (Test-Path $Path) {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            $value = $item.$Name; $existed = $true
            $type = (Get-Item $Path).GetValueKind($Name).ToString()
        }
    } catch { $existed = $false }
    $bk = [pscustomobject]@{ Path=$Path; Name=$Name; Existed=$existed; Value=$value; Type=$type }
    [void]$Context.Backups.Add($bk)
    Write-CmmcLog -Context $Context -Message ("backup: {0}\{1} = '{2}' (existed={3})" -f $Path,$Name,$value,$existed) -Level INFO
    return $bk
}

function Set-CmmcRegistry {
    param(
        [Parameter(Mandatory)]$Context,[Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,[ValidateSet('DWord','String','ExpandString','MultiString','QWord','Binary')][string]$Type='DWord'
    )
    Backup-CmmcRegistry -Context $Context -Path $Path -Name $Name | Out-Null
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-CmmcLog -Context $Context -Message ("applied: {0}\{1} = '{2}' ({3})" -f $Path,$Name,$Value,$Type) -Level ENFORCE
}

function Complete-CmmcRun {
    param([Parameter(Mandatory)]$Context,[string]$Title)
    if (-not $Title) { $Title = $Context.ScriptId }

    $pass = @($Context.Results | Where-Object Result -eq 'PASS').Count
    $fail = @($Context.Results | Where-Object Result -eq 'FAIL').Count
    $na   = @($Context.Results | Where-Object Result -eq 'N/A').Count
    $info = @($Context.Results | Where-Object Result -eq 'INFO').Count
    $enf  = @($Context.Results | Where-Object Result -eq 'ENFORCED').Count
    $err  = @($Context.Results | Where-Object Result -eq 'ERROR').Count

    $failC1 = @($Context.Results | Where-Object { $_.Result -eq 'FAIL' -and $_.Severity -eq 'CAT I'   }).Count
    $failC2 = @($Context.Results | Where-Object { $_.Result -eq 'FAIL' -and $_.Severity -eq 'CAT II'  }).Count
    $failC3 = @($Context.Results | Where-Object { $_.Result -eq 'FAIL' -and $_.Severity -eq 'CAT III' }).Count

    $stigCount = @($Context.Results | Where-Object { $_.STIG_ID -and $_.STIG_ID -ne '[확인필요]' } |
        Select-Object -ExpandProperty STIG_ID -Unique).Count

    $footer = "RESULT_SUMMARY script={0} mode={1} pass={2} fail={3} na={4} info={5} enforced={6} error={7} failCATI={8} failCATII={9} failCATIII={10} stig_ids={11}" -f `
        $Context.ScriptId,$Context.Mode,$pass,$fail,$na,$info,$enf,$err,$failC1,$failC2,$failC3,$stigCount

    if ($Context.Backups.Count -gt 0) {
        try {
            if (-not (Test-Path $Context.BackupDir)) { New-Item -ItemType Directory -Path $Context.BackupDir -Force | Out-Null }
            $Context.Backups | ConvertTo-Json -Depth 5 | Set-Content -Path $Context.BackupFile -Encoding UTF8
            Write-CmmcLog -Context $Context -Message ("rollback note: pre-change values saved to {0}. To restore, reset each item to its original value (delete items whose existed=false)." -f $Context.BackupFile) -Level WARN
        } catch { Write-CmmcLog -Context $Context -Message ("backup save error: " + $_.Exception.Message) -Level ERROR }
    }

    Write-CmmcLog -Context $Context -Message $footer -Level INFO -Always
    Write-CmmcLog -Context $Context -Message ("=== {0} [{1}] end ===" -f $Context.ScriptId,$Context.Mode) -Level INFO
}
