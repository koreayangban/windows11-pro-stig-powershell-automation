# 점검값만 콘솔에 출력합니다.
# Windows 11, PowerShell 5.1

[CmdletBinding()]
param(
    [string]$Mode = 'Check',
    [string]$BaselinePath,
    [string[]]$Only,
    [switch]$Quiet,
    [Alias('Usage','h')][switch]$Help
)

. "$PSScriptRoot\_CmmcCommon.ps1"

if (-not $BaselinePath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
    $BaselinePath = Join-Path $root 'STIG_Win11_Baseline.csv'
}
$script:CmmcMeta = @{
    Name     = '15_STIG_Win11_Check'
    Purpose  = 'STIG_Win11_Baseline.csv를 소비해 settable 항목(registry/secpol/auditpol)의 현재값을 Effective_Expected와 비교(읽기 전용 오프라인 점검).'
    Modes    = 'Check only'
    Scope    = 'DISA Windows 11 STIG V2R7 / CMMC CM.L2-3.4.1, CM.L2-3.4.2, CA.L2-3.12.3'
    Params   = '-BaselinePath, -Only (advanced)'
    Examples = @('.\15_STIG_Win11_Check.ps1 -Mode Check', '.\15_STIG_Win11_Check.ps1 -Help')
}
if ($Help) { Show-CmmcUsage $script:CmmcMeta; exit 0 }
$resolvedMode = Resolve-CmmcMode $Mode
if (-not $resolvedMode) { Write-Host '[ERROR] -Mode must be Check or Enforce (abbrev c/e ok).' -ForegroundColor Red; Show-CmmcUsage $script:CmmcMeta; exit 2 }
$Mode = $resolvedMode
$ctx = Initialize-CmmcRun -ScriptId '15_STIG_Win11_Check' -Mode $Mode -Quiet:$Quiet

function Convert-Hive([string]$h) {
    switch -regex ($h) {
        'LOCAL_MACHINE|^HKLM' { 'HKLM:' ; break }
        'CURRENT_USER|^HKCU'  { 'HKCU:' ; break }
        'USERS'               { 'HKU:'  ; break }
        'CLASSES_ROOT'        { 'HKCR:' ; break }
        default               { 'HKLM:' }
    }
}

function Get-RegValue($hive, $path, $name) {
    try {
        $full = (Convert-Hive $hive) + ($path.TrimEnd('\'))
        if (-not (Test-Path $full)) { return $null }
        $p = Get-ItemProperty -Path $full -Name $name -ErrorAction Stop
        return $p.$name
    } catch { return $null }
}

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

function Read-CmmcUserRegValue($prof, $keyPathHkcu, $name) {
    if ($prof.Loaded) {
        $full = ("Registry::HKEY_USERS\" + $prof.SID) + $keyPathHkcu.TrimEnd('\')
        try { if (Test-Path $full) { return (Get-ItemProperty $full -Name $name -ErrorAction Stop).$name } } catch {}
        return $null
    }
    $mount = 'CMMC_' + ([guid]::NewGuid().ToString('N').Substring(0,8)); $ok = $false
    try {
        & reg load ("HKU\" + $mount) $prof.NtUser 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $ok = $true } else { return $null }
        $full = ("Registry::HKEY_USERS\" + $mount) + $keyPathHkcu.TrimEnd('\')
        if (Test-Path $full) { try { return (Get-ItemProperty $full -Name $name -ErrorAction Stop).$name } catch {} }
        return $null
    } finally { if ($ok) { [gc]::Collect(); & reg unload ("HKU\" + $mount) 2>$null | Out-Null } }
}

$script:SecCache = $null
function Get-SeceditDb {
    if ($null -ne $script:SecCache) { return $script:SecCache }

    $tmpRoot = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $tmp = Join-Path $tmpRoot ('cmmc_sec_{0}.inf' -f (Get-CmmcTimestamp -ForFile))
    $db = @{}
    try {
        secedit /export /cfg $tmp /quiet | Out-Null
        foreach ($line in Get-Content -Path $tmp -ErrorAction Stop) {
            if ($line -match '^\s*([A-Za-z0-9]+)\s*=\s*(.+?)\s*$') { $db[$matches[1]] = $matches[2] }
        }
    } catch {}
    finally { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue }
    $script:SecCache = $db
    return $db
}

$script:AuditByGuid = $null
function Get-AuditGuidMap {
    if ($null -ne $script:AuditByGuid) { return $script:AuditByGuid }
    $map = @{}
    try {
        $raw = & auditpol /get /category:* /r 2>$null
        if ($LASTEXITCODE -eq 0 -and $raw) {
            $parsed = $raw | Where-Object { $_ -and $_ -notmatch '^Machine Name,' } |
                ConvertFrom-Csv -Header 'Machine','Target','Subcategory','Guid','Setting','S2','S3'
            foreach ($p in $parsed) { if ($p.Guid) { $map[$p.Guid.Trim().ToLower()] = $p.Setting.Trim() } }
        }
    } catch {}
    $script:AuditByGuid = $map
    return $map
}

function Test-Match($actual, $expected, $note) {
    if ($null -eq $actual) { return $false }
    $a = "$actual"; $e = "$expected"
    if ($e -match '^>=\s*(\d+)$') { return ([int64]$a -ge [int64]$matches[1]) }
    if ($note -match 'or greater') { if ($a -match '^\d+$' -and $e -match '^\d+$') { return ([int64]$a -ge [int64]$e) } }
    if ($note -match 'or less')    { if ($a -match '^\d+$' -and $e -match '^\d+$') { return ([int64]$a -le [int64]$e) } }
    if ($a -match '^\d+$' -and $e -match '^\d+$') { return ([int64]$a -eq [int64]$e) }
    return ($a -eq $e)
}

if (-not (Test-Path $BaselinePath)) {
    Write-CmmcLog -Context $ctx -Message ("Baseline not found: {0}" -f $BaselinePath) -Level ERROR
    Complete-CmmcRun -Context $ctx -Title 'Windows 11 STIG Check (V2R7)'
    return
}
$baseline = Import-Csv -Path $BaselinePath
if ($Only) { $baseline = $baseline | Where-Object { $Only -contains $_.STIG_ID } }
Write-CmmcLog -Context $ctx -Message ("Loaded baseline rows: {0}" -f $baseline.Count) -Level INFO

$verdicts = @{}
foreach ($r in $baseline) {
    $sid = $r.STIG_ID; $method = $r.Method; $eff = $r.Effective_Expected; $stig = $r.STIG_Expected; $odp = $r.ODP_Override
    $verdict = 'MANUAL'; $actual = ''
    try {
        switch ($method) {
            'NA'            { $verdict = 'NA'; $actual = 'n/a' }
            'manual-bios'   { $verdict = 'MANUAL'; $actual = 'BIOS (see BIOS_Boot_Checklist)' }
            'risk-accepted' { $verdict = 'RISK-ACCEPTED'; $actual = 'administrative control (risk acceptance)' }
            'registry' {
                if (-not $eff) { $verdict = 'MANUAL'; $actual = '(no expected; SCC-primary)'; break }
                if ($r.Scope -eq 'user') {

                    $profs = Get-CmmcUserProfiles | Where-Object { $_.SID -ne 'DEFAULT' }
                    $parts = @(); $allPass = $true; $any = $false
                    foreach ($p in $profs) {
                        $any = $true
                        $cv = Read-CmmcUserRegValue $p $r.KeyPath $r.ValueName
                        $ok = Test-Match $cv $eff $r.Notes
                        if (-not $ok) { $allPass = $false }
                        $parts += ('{0}={1}{2}' -f $p.Name, $(if($null -eq $cv){'(unset)'}else{"$cv"}), $(if($ok){'(ok)'}else{'(FAIL)'}))
                    }
                    $actual = 'per-user[' + ($parts -join '; ') + ']'
                    $verdict = if (-not $any) { 'MANUAL' } elseif ($allPass) { 'PASS' } else { 'FAIL' }
                } else {

                    $paths = @($r.KeyPath -split '\|')
                    $parts = @(); $allPass = $true
                    foreach ($kp in $paths) {
                        $cur = Get-RegValue $r.Hive $kp $r.ValueName
                        $ok = Test-Match $cur $eff $r.Notes
                        if (-not $ok) { $allPass = $false }
                        if ($paths.Count -gt 1) {
                            $leaf = if ($kp -match '\\(\w+file)\\') { $matches[1] } else { ($kp.TrimEnd('\') -split '\\')[-1] }
                            $parts += ('{0}={1}{2}' -f $leaf, $(if($null -eq $cur){'(unset)'}else{"$cur"}), $(if($ok){'(ok)'}else{'(FAIL)'}))
                        } else {
                            $parts += $(if ($null -eq $cur) { '(not set)' } else { "$cur" })
                        }
                    }
                    $actual = if ($paths.Count -gt 1) { '[' + ($parts -join '; ') + ']' } else { $parts[0] }
                    if ($allPass) {
                        $verdict = if ($odp -and ($eff -ne $stig) -and $stig) { 'DEVIATION' } else { 'PASS' }
                    } else { $verdict = 'FAIL' }
                }
            }
            'auditpol' {
                if (-not $eff -or -not $r.ValueName) { $verdict = 'MANUAL'; $actual = '(subcategory/expected missing)'; break }
                $guid = $r.AuditSubcategoryGuid
                if (-not $guid -or $guid -eq '[확인필요]') {

                    $verdict = 'MANUAL'; $actual = ("(no AuditSubcategoryGuid for '{0}'; verify via auditpol /get /category:* /r)" -f $r.ValueName); break
                }
                $amap = Get-AuditGuidMap
                if (-not $amap.ContainsKey($guid.ToLower())) {
                    $verdict = 'FAIL'; $actual = ("subcategory GUID {0} absent on this OS build" -f $guid)
                } else {
                    $cur = $amap[$guid.ToLower()]
                    $actual = if ($cur) { $cur } else { '(unknown)' }

                    $okS = ($eff -notmatch 'Success') -or ($cur -match 'Success|성공')
                    $okF = ($eff -notmatch 'Failure') -or ($cur -match 'Failure|실패')
                    $verdict = if ($okS -and $okF) { 'PASS' } else { 'FAIL' }
                }
            }
            'secpol' {
                $db = Get-SeceditDb
                $type = $r.Type
                if ($type -eq 'ACCOUNT') {
                    if ($sid -eq 'WN11-SO-000010') { $u = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like '*-501' }; $actual = if($u){"Enabled=$($u.Enabled)"}else{'?'}; $verdict = if($u -and -not $u.Enabled){'PASS'}else{'FAIL'} }
                    elseif ($sid -eq 'WN11-SO-000020') { $a = ($db['NewAdministratorName'] -replace '"',''); $actual = $a; $verdict = if($a -and $a -ne 'Administrator'){'PASS'}else{'FAIL'} }
                    elseif ($sid -eq 'WN11-SO-000025') { $g = ($db['NewGuestName'] -replace '"',''); $actual = $g; $verdict = if($g -and $g -ne 'Guest'){'PASS'}else{'FAIL'} }
                    else { $verdict = 'MANUAL' }
                }
                elseif ($type -eq 'USER_RIGHT') { $verdict = 'MANUAL'; $actual = '(user-right; review via secedit)' }
                elseif (-not $eff) { $verdict = 'MANUAL'; $actual = '(SCC-primary; manual review)' }
                else {
                    $map = @{ 'WN11-AC-000005'='LockoutDuration'; 'WN11-AC-000010'='LockoutBadCount'; 'WN11-AC-000015'='ResetLockoutCount';
                              'WN11-AC-000020'='PasswordHistorySize'; 'WN11-AC-000025'='MaximumPasswordAge'; 'WN11-AC-000030'='MinimumPasswordAge';
                              'WN11-AC-000035'='MinimumPasswordLength'; 'WN11-AC-000040'='PasswordComplexity'; 'WN11-AC-000045'='ClearTextPassword' }
                    if ($map.ContainsKey($sid)) {
                        $key = $map[$sid]; $cur = $db[$key]; $actual = "$cur"
                        $expCmp = $eff
                        if ($sid -eq 'WN11-AC-000040') { $expCmp = '1' }
                        if ($sid -eq 'WN11-AC-000045') { $expCmp = '0' }
                        if ($sid -eq 'WN11-AC-000025') {

                            $cn = $null
                            $ok = ([int]::TryParse(("" + $cur), [ref]$cn)) -and ($cn -eq 0 -or $cn -eq -1)
                        } else {
                            $ok = Test-Match $cur $expCmp $r.Notes
                        }
                        if ($ok) { $verdict = if ($odp -and ($eff -ne $stig) -and $stig) { 'DEVIATION' } else { 'PASS' } }
                        else { $verdict = 'FAIL' }
                    } else { $verdict = 'MANUAL'; $actual = '(secpol; manual review)' }
                }
            }
            'feature' {
                if (-not $eff) { $verdict = 'MANUAL'; $actual = '(no expected)'; break }
                try {
                    $st = (Get-WindowsOptionalFeature -Online -FeatureName $r.ValueName -ErrorAction Stop).State
                    $actual = "$st"
                    $verdict = if (("$st" -match 'Disabled' -and $eff -match 'Disabled') -or ("$st" -match 'Enabled' -and $eff -match 'Enabled')) { 'PASS' } else { 'FAIL' }
                } catch { $verdict = 'MANUAL'; $actual = ('feature query failed: ' + $_.Exception.Message) }
            }
            'service' {

                $svcName = $r.ValueName
                $cim = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcName) -ErrorAction SilentlyContinue
                if (-not $cim) {

                    $verdict = 'PASS'; $actual = ("service '{0}' absent (treated as disabled)" -f $svcName)
                } else {
                    $start = "$($cim.StartMode)"; $state = "$($cim.State)"
                    $actual = ("StartMode={0}; State={1}" -f $start, $state)
                    $verdict = if (($start -match 'Disabled') -and ($state -notmatch 'Running')) { 'PASS' } else { 'FAIL' }
                }
            }
            'covered-elsewhere' { $verdict = 'COVERED'; $actual = 'covered (see Notes)' }
            'manual' { $verdict = 'MANUAL'; $actual = '(manual: see Notes)' }
            'check-only' {
                if ($sid -eq 'WN11-00-000065') {
                    try {
                        $stale = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-35) }
                        $actual = if ($stale) { 'inactive>35d: ' + (($stale | ForEach-Object Name) -join ',') } else { 'none inactive>35d' }
                        $verdict = if ($stale) { 'FAIL' } else { 'PASS' }
                    } catch { $verdict = 'MANUAL'; $actual = ('enum failed: ' + $_.Exception.Message) }
                }
                elseif ($sid -eq 'WN11-00-000070') {
                    try {

                        $mem = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop

                        $bad = $mem | Where-Object { (($_.Name -split '\\')[-1] -notmatch '^priv_') -and -not ($_.SID -and $_.SID.Value -like '*-500') }
                        $actual = if ($bad) { 'non-priv_ admins: ' + (($bad | ForEach-Object Name) -join ',') } else { 'Administrators = priv_ only' }
                        $verdict = if ($bad) { 'FAIL' } else { 'PASS' }
                    } catch { $verdict = 'MANUAL'; $actual = ('enum failed: ' + $_.Exception.Message) }
                }
                else { $verdict = 'MANUAL'; $actual = '(check-only; manual review)' }
            }
            default { $verdict = 'MANUAL' }
        }
    } catch { $verdict = 'MANUAL'; $actual = ('error: ' + $_.Exception.Message) }

    $status = switch ($verdict) { 'PASS' {'PASS'} 'DEVIATION' {'PASS'} 'NA' {'N/A'} 'FAIL' {'FAIL'} default {'INFO'} }

    $dev = if ($verdict -eq 'DEVIATION' -and $stig) { "TAILORED(STIG={0})" -f $stig } else { '' }
    Add-CmmcResult -Context $ctx -Item ("{0} | {1}" -f $sid, $r.Severity) -Control $r.CMMC_Control `
        -StigId $sid -Severity $r.Severity -Cci $r.CCI -Deviation $dev `
        -Expected ("{0}={1}" -f $method, $eff) -Actual ("{0} [{1}]" -f $actual, $verdict) -Status $status `
        -Detail ("STIG {0}; ODP={1}; {2}" -f $sid, $odp, $r.Notes)
    $k = ('{0}|{1}' -f $r.Severity, $verdict); $verdicts[$k] = 1 + ([int]$verdicts[$k])
}

Write-CmmcLog -Context $ctx -Message '----- STIG Check summary (Severity x Verdict) -----' -Level INFO
foreach ($sev in @('CAT I','CAT II','CAT III')) {
    $line = $verdicts.Keys | Where-Object { $_ -like "$sev|*" } | ForEach-Object { '{0}={1}' -f ($_ -split '\|')[1], $verdicts[$_] }
    if ($line) { Write-CmmcLog -Context $ctx -Message ("{0}: {1}" -f $sev, ($line -join '  ')) -Level INFO }
}
Complete-CmmcRun -Context $ctx -Title 'Windows 11 STIG Check (V2R7, offline)'
