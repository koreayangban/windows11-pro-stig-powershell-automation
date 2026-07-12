param(
    [string]$Mode = 'Check',
    [switch]$Quiet,
    [Alias('Usage','h')][switch]$Help
)

. "$PSScriptRoot\_CmmcCommon.ps1"

$script:CmmcMeta = @{
    Name     = '01_PasswordPolicy'
    Purpose  = 'CMMC L2 패스워드 및 계정 잠금 정책 (Check / Enforce) — secedit 기준선 비교/적용.'
    Modes    = 'Check, Enforce'
    Scope    = 'IA.L2-3.5.7/8/10, AC.L2-3.1.8 / WN11-AC-000005,010,015,020,025,030,035,040,045'
    Examples = @('.\01_PasswordPolicy.ps1 -Mode Check', '.\01_PasswordPolicy.ps1 -Help')
}
if ($Help) { Show-CmmcUsage $script:CmmcMeta; exit 0 }
$resolvedMode = Resolve-CmmcMode $Mode
if (-not $resolvedMode) { Write-Host '[ERROR] -Mode must be Check or Enforce (abbrev c/e ok).' -ForegroundColor Red; Show-CmmcUsage $script:CmmcMeta; exit 2 }
$Mode = $resolvedMode

$ctx = Initialize-CmmcRun -ScriptId '01_PasswordPolicy' -Mode $Mode -Quiet:$Quiet

try {

    $expected = @{
        MinimumPasswordLength = 16
        PasswordHistorySize   = 24
        MaximumPasswordAge    = 0
        MinimumPasswordAge    = 1
        PasswordComplexity    = 1
        ClearTextPassword     = 0
        LockoutBadCount       = 3
        LockoutDuration       = 15
        ResetLockoutCount     = 15
    }

    $controls = @{
        MinimumPasswordLength = 'IA.L2-3.5.7'
        PasswordHistorySize   = 'IA.L2-3.5.8'
        MaximumPasswordAge    = 'IA.L2-3.5.10'
        MinimumPasswordAge    = 'IA.L2-3.5.10'
        PasswordComplexity    = 'IA.L2-3.5.7'
        ClearTextPassword     = 'IA.L2-3.5.10'
        LockoutBadCount       = 'AC.L2-3.1.8'
        LockoutDuration       = 'AC.L2-3.1.8'
        ResetLockoutCount     = 'AC.L2-3.1.8'
    }

    $stigIds = @{
        MinimumPasswordLength = 'WN11-AC-000035'
        PasswordHistorySize   = 'WN11-AC-000020'
        MaximumPasswordAge    = 'WN11-AC-000025'
        MinimumPasswordAge    = 'WN11-AC-000030'
        PasswordComplexity    = 'WN11-AC-000040'
        ClearTextPassword     = 'WN11-AC-000045'
        LockoutBadCount       = 'WN11-AC-000010'
        LockoutDuration       = 'WN11-AC-000005'
        ResetLockoutCount     = 'WN11-AC-000015'
    }
    $severities = @{
        MinimumPasswordLength = 'CAT II'
        PasswordHistorySize   = 'CAT II'
        MaximumPasswordAge    = 'CAT II'
        MinimumPasswordAge    = 'CAT II'
        PasswordComplexity    = 'CAT II'
        ClearTextPassword     = 'CAT I'
        LockoutBadCount       = 'CAT II'
        LockoutDuration       = 'CAT II'
        ResetLockoutCount     = 'CAT II'
    }
    $ccis = @{
        MinimumPasswordLength = 'CCI-004066;CCI-000205'
        PasswordHistorySize   = 'CCI-004061'
        MaximumPasswordAge    = 'CCI-004066;CCI-000199'
        MinimumPasswordAge    = 'CCI-004066;CCI-000198'
        PasswordComplexity    = 'CCI-004066;CCI-000192'
        ClearTextPassword     = 'CCI-004062;CCI-000196'
        LockoutBadCount       = 'CCI-000044'
        LockoutDuration       = 'CCI-002238'
        ResetLockoutCount     = 'CCI-000044'
    }

    $deviations = @{
        MinimumPasswordLength = 'TAILORED(STIG=14)'
        MaximumPasswordAge    = 'TAILORED(STIG=60)'
    }

    $exportPath = Join-Path $(if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }) ("secpol_export_{0}.inf" -f (Get-CmmcTimestamp -ForFile))
    Write-CmmcLog -Context $ctx -Message ("Exporting current security policy: secedit /export /cfg {0}" -f $exportPath) -Level INFO
    & secedit.exe /export /cfg "$exportPath" /quiet | Out-Null

    $current = @{}
    if (Test-Path $exportPath) {

        $lines = Get-Content -Path $exportPath -Encoding Unicode -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match '^\s*([A-Za-z]\w+)\s*=\s*(.+?)\s*$') {
                $current[$matches[1]] = $matches[2].Trim()
            }
        }

        $ctx | Add-Member -NotePropertyName SeceditBackup -NotePropertyValue $exportPath -Force
        Write-CmmcLog -Context $ctx -Message ("Security policy export parsed: {0} keys" -f $current.Count) -Level INFO
    } else {
        Write-CmmcLog -Context $ctx -Message 'secedit export file was not created; cannot read current policy.' -Level ERROR
    }

    foreach ($key in @('MinimumPasswordLength','PasswordHistorySize','MaximumPasswordAge','MinimumPasswordAge','PasswordComplexity','ClearTextPassword','LockoutBadCount','LockoutDuration','ResetLockoutCount')) {
        $exp = $expected[$key]
        $ctl = $controls[$key]
        if ($current.ContainsKey($key)) {
            $actualRaw = $current[$key]
            $actualNum = 0
            [void][int]::TryParse($actualRaw, [ref]$actualNum)

            $isPass = $false
            if ($key -eq 'MaximumPasswordAge') {

                $isPass = ($actualNum -eq 0 -or $actualNum -eq -1)
            } else {
                $isPass = ($actualNum -eq $exp)
            }

            Add-CmmcResult -Context $ctx -Item $key -Control $ctl `
                -Expected ([string]$exp) -Actual $actualRaw `
                -Status $(if ($isPass) { 'PASS' } else { 'FAIL' }) `
                -StigId $stigIds[$key] -Severity $severities[$key] -Cci $ccis[$key] -Deviation ([string]$deviations[$key])
        } else {
            Add-CmmcResult -Context $ctx -Item $key -Control $ctl `
                -Expected ([string]$exp) -Actual 'not found' -Status 'FAIL' `
                -Detail 'Setting was not present in the secedit export.' `
                -StigId $stigIds[$key] -Severity $severities[$key] -Cci $ccis[$key] -Deviation ([string]$deviations[$key])
        }
    }

    $complexityOn = ($current.ContainsKey('PasswordComplexity') -and $current['PasswordComplexity'] -eq '1')

    Add-CmmcResult -Context $ctx -Item 'UsernameNotInPassword' -Control 'IA.L2-3.5.7' `
        -Expected 'Enforced via complexity' -Actual ($(if ($complexityOn) { 'Complexity enabled' } else { 'Complexity disabled' })) `
        -Status ($(if ($complexityOn) { 'PASS' } else { 'FAIL' })) `
        -Detail 'Windows complexity policy rejects passwords that contain the account name (administrative control).' `
        -StigId '[확인필요]'

    $blocklistPath = Join-Path $PSScriptRoot 'blocklist.txt'
    if (Test-Path $blocklistPath) {
        $blCount = (Get-Content -Path $blocklistPath -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() -ne '' }).Count

        Add-CmmcResult -Context $ctx -Item 'PasswordBlocklist' -Control 'IA.L2-3.5.7' `
            -Expected 'blocklist.txt present' -Actual ("present ({0} entries)" -f $blCount) -Status 'INFO' `
            -Detail 'Banned/breached password list found. Apply via password filter or AD fine-grained policy (administrative control).' `
            -StigId '[확인필요]'
    } else {

        Add-CmmcResult -Context $ctx -Item 'PasswordBlocklist' -Control 'IA.L2-3.5.7' `
            -Expected 'blocklist.txt present' -Actual 'not found' -Status 'INFO' `
            -Detail 'No blocklist.txt in script folder. Provide a banned-password list as an administrative control (no internet lookup).' `
            -StigId '[확인필요]'
    }

    if ($Mode -eq 'Enforce') {
        if (-not (Test-CmmcAdmin)) {
            Write-CmmcLog -Context $ctx -Message 'Enforce requires administrator privileges; skipping changes.' -Level WARN

            Add-CmmcResult -Context $ctx -Item 'EnforcePrivilege' -Control 'AC.L2-3.1.8' `
                -Expected 'Administrator' -Actual 'Non-admin' -Status 'FAIL' `
                -Detail 'Re-run from an elevated PowerShell to apply the baseline.' `
                -StigId '[확인필요]'
        } else {

            if (-not (Test-Path $ctx.BackupDir)) { New-Item -ItemType Directory -Path $ctx.BackupDir -Force | Out-Null }
            $backupCopy = Join-Path $ctx.BackupDir ("secpol_backup_{0}.inf" -f (Get-CmmcTimestamp -ForFile))
            if (Test-Path $exportPath) {
                Copy-Item -Path $exportPath -Destination $backupCopy -Force
                Write-CmmcLog -Context $ctx -Message ("Pre-change security policy backed up to {0}" -f $backupCopy) -Level INFO
            }

            & net.exe accounts /minpwlen:16 /uniquepw:24 /maxpwage:unlimited /minpwage:1 | Out-Null
            & net.exe accounts /lockoutthreshold:3 /lockoutduration:15 /lockoutwindow:15 | Out-Null
            Write-CmmcLog -Context $ctx -Message 'Applied password length/history/age and lockout settings via net accounts.' -Level ENFORCE

            $infPath = Join-Path $(if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }) ("secpol_apply_{0}.inf" -f (Get-CmmcTimestamp -ForFile))
            $infBody = @"
[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 1
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
            Set-Content -Path $infPath -Value $infBody -Encoding Unicode
            $dbPath = Join-Path $(if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }) ("secpol_apply_{0}.sdb" -f (Get-CmmcTimestamp -ForFile))
            & secedit.exe /configure /db "$dbPath" /cfg "$infPath" /areas SECURITYPOLICY /quiet | Out-Null
            Write-CmmcLog -Context $ctx -Message 'Applied PasswordComplexity=1 and ClearTextPassword=0 via secedit /configure.' -Level ENFORCE

            Add-CmmcResult -Context $ctx -Item 'PasswordPolicyBaseline' -Control 'IA.L2-3.5.7' `
                -Expected 'Baseline applied' -Actual 'net accounts + secedit' -Status 'ENFORCED' `
                -Detail ("Length=16 History=24 MaxAge=unlimited MinAge=1 Complexity=1 ClearText=0. Backup: {0}" -f $backupCopy) `
                -StigId '[확인필요]'

            Add-CmmcResult -Context $ctx -Item 'AccountLockoutBaseline' -Control 'AC.L2-3.1.8' `
                -Expected 'Baseline applied' -Actual 'net accounts' -Status 'ENFORCED' `
                -Detail 'Threshold=3 Duration=15min ResetWindow=15min.' `
                -StigId '[확인필요]'

            foreach ($tmp in @($infPath, $dbPath)) {
                if (Test-Path $tmp) { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    if (Test-Path $exportPath) { Remove-Item -Path $exportPath -Force -ErrorAction SilentlyContinue }
}
catch {
    Write-CmmcLog -Context $ctx -Message $_.Exception.Message -Level ERROR
}

Complete-CmmcRun -Context $ctx -Title 'Password Policy'
