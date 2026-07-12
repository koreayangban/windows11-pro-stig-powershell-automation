# 일부 정책은 원상복구 후, 재부팅이 필요합니다.

[CmdletBinding()]
param(
    [string]$BackupDir,
    [switch]$Apply,
    [Alias('Usage','h')][switch]$Help
)

. "$PSScriptRoot\_CmmcCommon.ps1"

$script:CmmcMeta = @{
    Name     = 'STIG_Win11_Restore'
    Purpose  = '16_STIG_Win11_Enforce 백업(backup_<ts>)으로부터 reg/secedit/auditpol 롤백.'
    Modes    = 'WhatIf(기본) / -Apply(실제 복원)'
    Scope    = 'CM.L2-3.4.3, CA.L2-3.12.3'
    Params   = '-BackupDir <backup\backup_YYYYMMDD_HHMMSS> [-Apply]'
    Examples = @('.\STIG_Win11_Restore.ps1 -BackupDir .\backup\backup_YYYYMMDD_HHMMSS', '.\STIG_Win11_Restore.ps1 -BackupDir <dir> -Apply', '.\STIG_Win11_Restore.ps1 -Help')
}
if ($Help) { Show-CmmcUsage $script:CmmcMeta; exit 0 }
if (-not $BackupDir) { Write-Host '[ERROR] -BackupDir 는 필수입니다(복원할 backup_<ts> 폴더 경로).' -ForegroundColor Red; Show-CmmcUsage $script:CmmcMeta; exit 2 }
$mode = if ($Apply) { 'Enforce' } else { 'Check' }
$ctx = Initialize-CmmcRun -ScriptId 'STIG_Win11_Restore' -Mode $mode
Write-CmmcLog -Context $ctx -Message ("MODE = {0}" -f $(if($Apply){'APPLY (restore will run)'}else{'WHATIF (preview only)'})) -Level $(if($Apply){'WARN'}else{'INFO'})

if (-not (Test-Path $BackupDir)) {
    Write-CmmcLog -Context $ctx -Message ("Backup dir not found: {0}" -f $BackupDir) -Level ERROR
    Complete-CmmcRun -Context $ctx -Title 'Windows 11 STIG Restore'; return
}
Write-CmmcLog -Context $ctx -Message ("Backup dir: {0}" -f $BackupDir) -Level INFO

$regs = Get-ChildItem -Path $BackupDir -Filter *.reg -ErrorAction SilentlyContinue
foreach ($f in $regs) {
    if ($Apply) {
        try { & reg import $f.FullName 2>$null | Out-Null
              Add-CmmcResult -Context $ctx -Item ("reg import {0}" -f $f.Name) -Control 'CM.L2-3.4.3' -Expected 'restored' -Actual 'restored' -Status 'ENFORCED' -Detail $f.FullName }
        catch { Add-CmmcResult -Context $ctx -Item ("reg import {0}" -f $f.Name) -Expected 'restored' -Actual 'error' -Status 'INFO' -Detail $_.Exception.Message }
    } else {
        Add-CmmcResult -Context $ctx -Item ("reg import {0}" -f $f.Name) -Control 'CM.L2-3.4.3' -Expected 'restored' -Actual 'would import' -Status 'INFO' -Detail $f.FullName
    }
}

$sec = Join-Path $BackupDir 'secedit_before.inf'
if (Test-Path $sec) {
    if ($Apply) {
        try { secedit /configure /db (Join-Path $(if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }) 'cmmc_restore.sdb') /cfg $sec /overwrite /quiet | Out-Null
              Add-CmmcResult -Context $ctx -Item 'secedit restore' -Control 'CM.L2-3.4.3' -Expected 'restored' -Actual 'restored' -Status 'ENFORCED' -Detail $sec }
        catch { Add-CmmcResult -Context $ctx -Item 'secedit restore' -Expected 'restored' -Actual 'error' -Status 'INFO' -Detail $_.Exception.Message }
    } else {
        Add-CmmcResult -Context $ctx -Item 'secedit restore' -Control 'CM.L2-3.4.3' -Expected 'restored' -Actual 'would configure' -Status 'INFO' -Detail $sec
    }
} else { Write-CmmcLog -Context $ctx -Message 'secedit_before.inf not present (skip)' -Level INFO }

$aud = Join-Path $BackupDir 'auditpol_before.csv'
if (Test-Path $aud) {
    if ($Apply) {
        try { & auditpol /restore /file:$aud | Out-Null
              Add-CmmcResult -Context $ctx -Item 'auditpol restore' -Control 'CM.L2-3.4.3' -Expected 'restored' -Actual 'restored' -Status 'ENFORCED' -Detail $aud }
        catch { Add-CmmcResult -Context $ctx -Item 'auditpol restore' -Expected 'restored' -Actual 'error' -Status 'INFO' -Detail $_.Exception.Message }
    } else {
        Add-CmmcResult -Context $ctx -Item 'auditpol restore' -Control 'CM.L2-3.4.3' -Expected 'restored' -Actual 'would restore' -Status 'INFO' -Detail $aud
    }
} else { Write-CmmcLog -Context $ctx -Message 'auditpol_before.csv not present (skip)' -Level INFO }

Complete-CmmcRun -Context $ctx -Title ('Windows 11 STIG Restore [{0}]' -f $(if($Apply){'APPLY'}else{'WHATIF'}))
if (-not $Apply) { Write-CmmcLog -Context $ctx -Message 'Preview only. Re-run with -Apply to perform the restore.' -Level WARN }
Write-CmmcLog -Context $ctx -Message 'A reboot may be required for some restored policies to take effect.' -Level WARN
