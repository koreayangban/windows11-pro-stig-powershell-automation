# Windows 11, PowerShell 5.1
# 조치(-mode enforce) 전 백업만 backup\ 폴더에 파일로 남깁니다.

[CmdletBinding()]
param(
    [string]$Mode = 'Check',
    [switch]$Apply,
    [string[]]$Only,
    [string]$BaselinePath,
    [switch]$Quiet,
    [Alias('Usage','h')][switch]$Help
)

. "$PSScriptRoot\_CmmcCommon.ps1"

if (-not $BaselinePath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
    $BaselinePath = Join-Path $root 'STIG_Win11_Baseline.csv'
}
$script:CmmcMeta = @{
    Name     = '16_STIG_Win11_Enforce'
    Purpose  = 'STIG_Win11_Baseline.csv의 settable 항목(registry/secpol/auditpol)에 Effective_Expected(ODP 우선)를 적용'
    Modes    = 'Check, Enforce'
    Scope    = 'DISA Windows 11 STIG V2R7 / CM.L2-3.4.1, CM.L2-3.4.2, CA.L2-3.12.3'
    Params   = '-Apply, -Only <STIG-ID...>, -BaselinePath'
    Examples = @('.\16_STIG_Win11_Enforce.ps1 -Mode Check', '.\16_STIG_Win11_Enforce.ps1 -Help')
}
if ($Help) { Show-CmmcUsage $script:CmmcMeta; exit 0 }
$resolvedMode = Resolve-CmmcMode $Mode
if (-not $resolvedMode) { Write-Host '[ERROR] -Mode must be Check or Enforce (abbrev c/e ok).' -ForegroundColor Red; Show-CmmcUsage $script:CmmcMeta; exit 2 }
$Mode = $resolvedMode
if ($Mode -eq 'Enforce') { $Apply = $true }
$mode = if ($Apply) { 'Enforce' } else { 'Check' }
$ctx = Initialize-CmmcRun -ScriptId '16_STIG_Win11_Enforce' -Mode $mode -Quiet:$Quiet
Write-CmmcLog -Context $ctx -Message ("MODE = {0}" -f $(if($Apply){'APPLY (changes will be made)'}else{'WHATIF (preview only, no changes)'})) -Level $(if($Apply){'WARN'}else{'INFO'})

function Convert-Hive([string]$h) {
    switch -regex ($h) { 'LOCAL_MACHINE|^HKLM' {'HKLM:';break} 'CURRENT_USER|^HKCU' {'HKCU:';break} default {'HKLM:'} }
}
function Get-RegValue($hive,$path,$name){ try{ $f=(Convert-Hive $hive)+($path.TrimEnd('\')); if(-not(Test-Path $f)){return $null}; (Get-ItemProperty -Path $f -Name $name -ErrorAction Stop).$name }catch{ $null } }

function Test-Match-Lite($actual,$expected){ if($null -eq $actual){return $false}; $a="$actual";$e="$expected"; if($a -match '^\d+$' -and $e -match '^\d+$'){return ([int64]$a -eq [int64]$e)}; return ($a -eq $e) }

function Get-CmmcUserProfiles {
    $list = @()
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = Split-Path $_.PSChildName -Leaf
        if ($sid -notmatch '^S-1-5-21-') { return }
        $img = (Get-ItemProperty $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $img) { return }
        $list += [pscustomobject]@{ SID=$sid; Name=(Split-Path $img -Leaf); Loaded=(Test-Path ("Registry::HKEY_USERS\" + $sid)); NtUser=(Join-Path $img 'NTUSER.DAT') }
    }
    $def = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
    if (Test-Path $def) { $list += [pscustomobject]@{ SID='DEFAULT'; Name='Default'; Loaded=$false; NtUser=$def } }
    return $list
}

function Set-CmmcUserRegValue($prof,$keyPathHkcu,$name,$val,$type,$backupDir,$sid){
    $mount=$null; $loaded=$false
    try{
        if($prof.Loaded){ $root="Registry::HKEY_USERS\"+$prof.SID; $hiveCli="HKU\"+$prof.SID }
        else{
            Copy-Item $prof.NtUser (Join-Path $backupDir ("NTUSER_{0}.DAT" -f $prof.Name)) -Force -ErrorAction SilentlyContinue
            $mount='CMMC_'+([guid]::NewGuid().ToString('N').Substring(0,8))
            & reg load ("HKU\"+$mount) $prof.NtUser 2>$null | Out-Null
            if($LASTEXITCODE -ne 0){ throw ("reg load failed: "+$prof.NtUser) }
            $loaded=$true; $root="Registry::HKEY_USERS\"+$mount; $hiveCli="HKU\"+$mount
        }
        $full=$root+$keyPathHkcu.TrimEnd('\')
        if($prof.Loaded){ & reg export ($hiveCli+$keyPathHkcu.TrimEnd('\')) (Join-Path $backupDir (("{0}_{1}_{2}.reg" -f $sid,$prof.Name,$name) -replace '[^A-Za-z0-9_.]','_')) /y 2>$null | Out-Null }
        if(-not (Test-Path $full)){ New-Item -Path $full -Force | Out-Null }
        New-ItemProperty -Path $full -Name $name -Value $val -PropertyType $type -Force | Out-Null
    } finally { if($loaded){ [gc]::Collect(); & reg unload ("HKU\"+$mount) 2>$null | Out-Null } }
}

$script:AuditGuidSet = $null
function Get-CurrentAuditGuids {
    if ($null -ne $script:AuditGuidSet) { return $script:AuditGuidSet }
    $set = @{}
    try {
        $raw = & auditpol /get /category:* /r 2>$null
        if ($LASTEXITCODE -eq 0 -and $raw) {
            $parsed = $raw | Where-Object { $_ -and $_ -notmatch '^Machine Name,' } |
                ConvertFrom-Csv -Header 'Machine','Target','Subcategory','Guid','Setting','S2','S3'
            foreach ($p in $parsed) { if ($p.Guid) { $set[$p.Guid.Trim().ToLower()] = $true } }
        }
    } catch {}
    $script:AuditGuidSet = $set
    return $set
}

if (-not (Test-Path $BaselinePath)) { Write-CmmcLog -Context $ctx -Message ("Baseline not found: {0}" -f $BaselinePath) -Level ERROR; Complete-CmmcRun -Context $ctx -Title 'Windows 11 STIG Enforce'; return }
$baseline = Import-Csv -Path $BaselinePath
if ($Only) { $baseline = $baseline | Where-Object { $Only -contains $_.STIG_ID } }

$backupDir = Join-Path $ctx.BackupDir ('backup_{0}' -f (Get-CmmcTimestamp -ForFile))
if ($Apply) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Write-CmmcLog -Context $ctx -Message ("Backup dir: {0}" -f $backupDir) -Level INFO
    try { secedit /export /cfg (Join-Path $backupDir 'secedit_before.inf') /quiet | Out-Null } catch {}
    try { & auditpol /backup /file:(Join-Path $backupDir 'auditpol_before.csv') | Out-Null } catch {}
}

$applied = New-Object System.Collections.ArrayList
$rebootList = New-Object System.Collections.ArrayList

$auditAgg = @{}
foreach ($br in $baseline) {
    if ($br.Method -ne 'auditpol') { continue }
    $g = $br.AuditSubcategoryGuid
    if (-not $g -or $g -eq '[확인필요]') { continue }
    $gk = $g.Trim().ToLower()
    if (-not $auditAgg.ContainsKey($gk)) { $auditAgg[$gk] = [pscustomobject]@{ Guid=$g.Trim(); Succ=$false; Fail=$false } }
    if ($br.Effective_Expected -match 'Success') { $auditAgg[$gk].Succ = $true }
    if ($br.Effective_Expected -match 'Failure') { $auditAgg[$gk].Fail = $true }
}
$auditSetDone = @{}

foreach ($r in $baseline) {
    $sid = $r.STIG_ID; $method = $r.Method; $eff = $r.Effective_Expected

    if ($method -in @('manual-bios','risk-accepted','NA','check-only','covered-elsewhere','manual')) {
        Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI `
            -Expected $eff -Actual 'skipped' -Status 'INFO' -Detail ("Method={0} (not auto-enforced): {1}" -f $method,$r.Notes)
        continue
    }
    if (-not $eff) {
        Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI `
            -Expected '(none)' -Actual 'skipped' -Status 'INFO' -Detail ("No Effective_Expected (SCC-primary/manual): {0}" -f $r.Notes)
        continue
    }

    switch ($method) {
        'registry' {
            if ($r.Scope -eq 'user') {

                $utype = if ($r.Type -match 'DWORD') { 'DWord' } elseif ($r.Type -match 'MULTI') { 'MultiString' } elseif ($r.Type -match 'SZ') { 'String' } else { 'DWord' }
                $uval = if ($utype -eq 'DWord') { [int]$eff } elseif ($utype -eq 'MultiString') { @($eff -split '\s+') } else { $eff }
                foreach ($p in (Get-CmmcUserProfiles)) {
                    if ($Apply) {
                        try { Set-CmmcUserRegValue $p $r.KeyPath $r.ValueName $uval $utype $backupDir $sid; [void]$applied.Add($sid)
                              Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("profile {0}: set {1} [ENFORCED]" -f $p.Name,$eff) -Status 'ENFORCED' -Detail ("HKCU {0}\{1} (per-user)" -f $r.KeyPath,$r.ValueName) }
                        catch { Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'error' -Status 'INFO' -Detail ("profile {0}: {1}" -f $p.Name,$_.Exception.Message) }
                    } else {
                        Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("would set profile {0} HKCU{1}\{2} -> {3}" -f $p.Name,$r.KeyPath,$r.ValueName,$eff) -Status 'INFO' -Detail 'WHATIF per-user (all profiles + Default)'
                    }
                }
                if ($r.RebootRequired -eq 'Y') { [void]$rebootList.Add($sid) }
            } else {

            $paths = @($r.KeyPath -split '\|')
            $type = if ($r.Type -match 'DWORD') { 'DWord' } elseif ($r.Type -match 'MULTI') { 'MultiString' } elseif ($r.Type -match 'SZ') { 'String' } else { 'DWord' }
            $val  = if ($type -eq 'DWord') { [int]$eff } elseif ($type -eq 'MultiString') { @($eff -split '\s+') } else { $eff }
            $beforeParts = @()
            foreach ($kp in $paths) {
                $b = Get-RegValue $r.Hive $kp $r.ValueName
                if ($paths.Count -gt 1) {
                    $leaf = if ($kp -match '\\(\w+file)\\') { $matches[1] } else { ($kp.TrimEnd('\') -split '\\')[-1] }
                    $beforeParts += ('{0}={1}' -f $leaf, $(if($null -eq $b){'(not set)'}else{"$b"}))
                } else { $beforeParts += $(if ($null -eq $b) { '(not set)' } else { "$b" }) }
            }
            $beforeTxt = if ($paths.Count -gt 1) { '[' + ($beforeParts -join '; ') + ']' } else { $beforeParts[0] }
            $pathTag = if ($paths.Count -gt 1) { " ({0} paths)" -f $paths.Count } else { '' }
            if ($Apply) {
                try {
                    $regHiveCli = (Convert-Hive $r.Hive).Replace(':','')
                    $i = 0
                    foreach ($kp in $paths) {
                        $full = (Convert-Hive $r.Hive) + ($kp.TrimEnd('\'))

                        $suffix = if ($paths.Count -gt 1) { '_' + $i } else { '' }
                        $exp = Join-Path $backupDir (($sid + '_' + $r.ValueName + $suffix) -replace '[^A-Za-z0-9_]','_') ; $exp += '.reg'
                        & reg export ($regHiveCli + ($kp.TrimEnd('\'))) $exp /y 2>$null | Out-Null
                        if (-not (Test-Path $full)) { New-Item -Path $full -Force | Out-Null }
                        New-ItemProperty -Path $full -Name $r.ValueName -Value $val -PropertyType $type -Force | Out-Null
                        $i++
                    }
                    [void]$applied.Add($sid)
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI `
                        -Expected $eff -Actual ("{0} -> {1} [ENFORCED]" -f $beforeTxt,$eff) -Status 'ENFORCED' -Detail ("registry {0}\{1}{2}" -f $r.KeyPath,$r.ValueName,$pathTag)
                } catch {
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'error' -Status 'INFO' -Detail ('enforce failed: ' + $_.Exception.Message)
                }
            } else {
                $allCompliant = $true
                foreach ($kp in $paths) { if (-not (Test-Match-Lite (Get-RegValue $r.Hive $kp $r.ValueName) $eff)) { $allCompliant = $false } }
                $would = if ($allCompliant) { 'already-compliant' } else { ("would set {0} -> {1}" -f $beforeTxt,$eff) }
                Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual $would -Status 'INFO' -Detail ("WHATIF registry {0}\{1}{2}" -f $r.KeyPath,$r.ValueName,$pathTag)
            }
            if ($r.RebootRequired -eq 'Y') { [void]$rebootList.Add($sid) }
            }
        }
        'auditpol' {
            $sub  = $r.ValueName
            $guid = $r.AuditSubcategoryGuid
            if (-not $guid -or $guid -eq '[확인필요]') {

                Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("no AuditSubcategoryGuid (name='{0}')" -f $sub) -Status 'INFO' -Detail 'auditpol enforce skipped: GUID 미해결([확인필요]). auditpol /get /category:* /r 로 확인 후 베이스라인에 채울 것.'
            }
            elseif (-not (Get-CurrentAuditGuids).ContainsKey($guid.ToLower())) {

                Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("subcategory GUID {0} absent on this OS build" -f $guid) -Status 'FAIL' -Detail ("auditpol enforce skipped: GUID not present on this OS (name='{0}')" -f $sub)
            }
            else {

                $gk = $guid.Trim().ToLower()
                $agg = $auditAgg[$gk]
                $succ = if ($agg -and $agg.Succ) { 'enable' } else { 'disable' }
                $fail = if ($agg -and $agg.Fail) { 'enable' } else { 'disable' }
                if ($Apply) {
                    try {

                        if (-not $auditSetDone.ContainsKey($gk)) {
                            & auditpol /set /subcategory:"$guid" /success:$succ /failure:$fail | Out-Null
                            $auditSetDone[$gk] = $true
                        }
                        [void]$applied.Add($sid)
                        Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("set success:{0} failure:{1} [ENFORCED]" -f $succ,$fail) -Status 'ENFORCED' -Detail ("auditpol subcategory '{0}' (GUID {1}; union per-subcategory)" -f $sub,$guid)
                    } catch {
                        Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'error' -Status 'INFO' -Detail ('enforce failed: ' + $_.Exception.Message)
                    }
                } else {
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("would set success:{0} failure:{1}" -f $succ,$fail) -Status 'INFO' -Detail ("WHATIF auditpol '{0}' (GUID {1}; union per-subcategory)" -f $sub,$guid)
                }
            }
        }
        'secpol' {

            $map = @{ 'WN11-AC-000005'='LockoutDuration'; 'WN11-AC-000010'='LockoutBadCount'; 'WN11-AC-000015'='ResetLockoutCount';
                      'WN11-AC-000020'='PasswordHistorySize'; 'WN11-AC-000025'='MaximumPasswordAge'; 'WN11-AC-000030'='MinimumPasswordAge';
                      'WN11-AC-000035'='MinimumPasswordLength'; 'WN11-AC-000040'='PasswordComplexity'; 'WN11-AC-000045'='ClearTextPassword' }
            if ($map.ContainsKey($sid)) {
                $key = $map[$sid]
                $val = $eff
                if ($sid -eq 'WN11-AC-000040') { $val = '1' }
                if ($sid -eq 'WN11-AC-000045') { $val = '0' }
                if ($Apply) {
                    try {
                        $inf = Join-Path $(if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }) ('cmmc_set_{0}.inf' -f $sid)
                        @('[Unicode]','Unicode=yes','[System Access]', ("{0} = {1}" -f $key,$val), '[Version]','signature="$CHICAGO$"','Revision=1') | Set-Content -Path $inf -Encoding Unicode
                        secedit /configure /db (Join-Path $(if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }) 'cmmc_secedit.sdb') /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
                        Remove-Item $inf -Force -ErrorAction SilentlyContinue
                        [void]$applied.Add($sid)
                        Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("secedit {0}={1} [ENFORCED]" -f $key,$val) -Status 'ENFORCED' -Detail ("ODP={0}; {1}" -f $r.ODP_Override,$r.Notes)
                    } catch {
                        Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'error' -Status 'INFO' -Detail ('enforce failed: ' + $_.Exception.Message)
                    }
                } else {
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("would set secedit {0}={1}" -f $key,$val) -Status 'INFO' -Detail ("WHATIF secpol; ODP={0}" -f $r.ODP_Override)
                }
            } else {
                Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'manual (not auto-enforced)' -Status 'INFO' -Detail ("secpol {0} requires manual/secpol action: {1}" -f $r.Type,$r.Notes)
            }
        }
        'feature' {
            $fn = $r.ValueName
            if ($Apply) {
                try {
                    $cur = (Get-WindowsOptionalFeature -Online -FeatureName $fn -ErrorAction Stop).State
                    ("FeatureName={0} State(before)={1}" -f $fn,$cur) | Set-Content -Path (Join-Path $backupDir ("feature_{0}.txt" -f $fn)) -Encoding UTF8
                    if ($eff -match 'Disabled') { Disable-WindowsOptionalFeature -Online -FeatureName $fn -NoRestart -ErrorAction Stop | Out-Null }
                    elseif ($eff -match 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName $fn -NoRestart -ErrorAction Stop | Out-Null }
                    [void]$applied.Add($sid)
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("{0} -> {1} [ENFORCED]" -f $cur,$eff) -Status 'ENFORCED' -Detail ("optional-feature {0}" -f $fn)
                } catch {
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'error' -Status 'INFO' -Detail ('enforce failed: ' + $_.Exception.Message)
                }
            } else {
                Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("would set feature {0} -> {1}" -f $fn,$eff) -Status 'INFO' -Detail ("WHATIF optional-feature {0}" -f $fn)
            }
            [void]$rebootList.Add($sid)
        }
        'service' {

            $svcName = $r.ValueName
            $cim = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcName) -ErrorAction SilentlyContinue
            $beforeStart = if ($cim) { "$($cim.StartMode)" } else { '(absent)' }
            $beforeState = if ($cim) { "$($cim.State)" } else { '(absent)' }
            if (-not $cim) {
                Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("service '{0}' absent (already non-running)" -f $svcName) -Status 'INFO' -Detail 'service not present; nothing to enforce'
            } elseif ($Apply) {
                try {
                    ("Service={0} StartMode(before)={1} State(before)={2}" -f $svcName,$beforeStart,$beforeState) | Set-Content -Path (Join-Path $backupDir ("service_{0}.txt" -f $svcName)) -Encoding UTF8
                    Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                    if ($beforeState -match 'Running') { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue }
                    [void]$applied.Add($sid)
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("StartMode {0}->Disabled (+stop if running) [ENFORCED]" -f $beforeStart) -Status 'ENFORCED' -Detail ("service '{0}' disabled (Start=4 동등)" -f $svcName)
                } catch {
                    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'error' -Status 'INFO' -Detail ('enforce failed: ' + $_.Exception.Message)
                }
            } else {
                Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual ("would set service '{0}' StartMode {1}->Disabled (+stop if running)" -f $svcName,$beforeStart) -Status 'INFO' -Detail ("WHATIF service '{0}'" -f $svcName)
            }
            if ($r.RebootRequired -eq 'Y') { [void]$rebootList.Add($sid) }
        }
        default {
            Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid,$r.Severity) -Control $r.CMMC_Control -StigId $sid -Severity $r.Severity -Cci $r.CCI -Expected $eff -Actual 'skipped' -Status 'INFO' -Detail ("unhandled method: {0}" -f $method)
        }
    }
}

if ($Apply -and $applied.Count -gt 0) {
    Write-CmmcLog -Context $ctx -Message ("Applied {0} items. Running post-enforce re-check (15_STIG_Win11_Check -Only ...)" -f $applied.Count) -Level INFO
    $checkScript = Join-Path $PSScriptRoot '15_STIG_Win11_Check.ps1'
    if (Test-Path $checkScript) {
        try { & $checkScript -BaselinePath $BaselinePath -Only $applied.ToArray() } catch { Write-CmmcLog -Context $ctx -Message ('re-check failed: ' + $_.Exception.Message) -Level WARN }
    }
}
if ($rebootList.Count -gt 0) { Write-CmmcLog -Context $ctx -Message ("RebootRequired items: {0}" -f ($rebootList -join ', ')) -Level WARN }

Complete-CmmcRun -Context $ctx -Title ('Windows 11 STIG Enforce (V2R7) [{0}]' -f $(if($Apply){'APPLY'}else{'WHATIF'}))
if ($Apply) { Write-CmmcLog -Context $ctx -Message ("ROLLBACK: restore with  STIG_Win11_Restore.ps1 -BackupDir '{0}' -Apply" -f $backupDir) -Level WARN }
