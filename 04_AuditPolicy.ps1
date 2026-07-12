param(
    [string]$Mode = 'Check',
    [switch]$Quiet,
    [Alias('Usage','h')][switch]$Help
)
. "$PSScriptRoot\_CmmcCommon.ps1"
$script:CmmcMeta = @{
    Name     = '04_AuditPolicy'
    Purpose  = 'Windows 고급 감사 정책을 점검/적용하여 DoD ODP 이벤트 유형이 기록되도록 보장.'
    Modes    = 'Check, Enforce'
    Scope    = 'AU.L2-3.3.1 / AU.L2-3.3.2 (WN11-AU-*)'
    Examples = @('.\04_AuditPolicy.ps1 -Mode Check', '.\04_AuditPolicy.ps1 -Help')
}
if ($Help) { Show-CmmcUsage $script:CmmcMeta; exit 0 }
$resolvedMode = Resolve-CmmcMode $Mode
if (-not $resolvedMode) { Write-Host '[ERROR] -Mode must be Check or Enforce (abbrev c/e ok).' -ForegroundColor Red; Show-CmmcUsage $script:CmmcMeta; exit 2 }
$Mode = $resolvedMode
$ctx = Initialize-CmmcRun -ScriptId '04_AuditPolicy' -Mode $Mode -Quiet:$Quiet
try {

    $required = @(

        [pscustomobject]@{ Sub='Logon';                        Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$true;  Group='Logon/Logoff'; StigId='WN11-AU-000075;WN11-AU-000070'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='Logoff';                       Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$false; Group='Logon/Logoff'; StigId='WN11-AU-000065'; Sev='CAT II'; Cci='CCI-000067'; Dev='' }

        [pscustomobject]@{ Sub='Account Lockout';              Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$false; Failure=$true;  Group='Logon/Logoff'; StigId='WN11-AU-000054'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='User Account Management';      Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.2'; Success=$true; Failure=$true;  Group='Account Management'; StigId='WN11-AU-000040;WN11-AU-000035'; Sev='CAT II'; Cci='CCI-001403;CCI-001314'; Dev='' }

        [pscustomobject]@{ Sub='Security Group Management';    Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.2'; Success=$true; Failure=$false;  Group='Account Management'; StigId='WN11-AU-000030'; Sev='CAT II'; Cci='CCI-001914'; Dev='' }

        [pscustomobject]@{ Sub='Computer Account Management';  Guid='{0CCE9236-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.2'; Success=$true; Failure=$true;  Group='Account Management'; StigId='[확인필요]'; Sev=''; Cci=''; Dev='TAILORED(STIG 비요구; 워크그룹 NA·무해)' }

        [pscustomobject]@{ Sub='File System';                  Guid='{0CCE921D-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$true;  Group='Object Access'; StigId='WN11-AU-000582;WN11-AU-000581'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='Registry';                     Guid='{0CCE921E-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$true;  Group='Object Access'; StigId='WN11-AU-000586;WN11-AU-000589'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='Removable Storage';            Guid='{0CCE9245-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$true;  Group='Object Access'; StigId='WN11-AU-000090;WN11-AU-000085'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='Sensitive Privilege Use';      Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.2'; Success=$true; Failure=$true;  Group='Privilege Use'; StigId='WN11-AU-000115;WN11-AU-000110'; Sev='CAT II'; Cci='CCI-000172;CCI-002234'; Dev='' }

        [pscustomobject]@{ Sub='Audit Policy Change';          Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$false;  Group='Policy Change'; StigId='WN11-AU-000100'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='Authentication Policy Change'; Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$false; Group='Policy Change'; StigId='WN11-AU-000105'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='Security State Change';        Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$false;  Group='System'; StigId='WN11-AU-000140'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='System Integrity';             Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.1'; Success=$true; Failure=$true;  Group='System'; StigId='WN11-AU-000160;WN11-AU-000155'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }

        [pscustomobject]@{ Sub='Process Creation';            Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.2'; Success=$true; Failure=$true; Group='Detailed Tracking (application execution)'; StigId='WN11-AU-000050;WN11-AU-000585'; Sev='CAT II'; Cci='CCI-000172;CCI-003938;CCI-001814;CCI-002234'; Dev='' }

        [pscustomobject]@{ Sub='Credential Validation';        Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; Control='AU.L2-3.3.2'; Success=$true; Failure=$true;  Group='Account Logon'; StigId='WN11-AU-000010;WN11-AU-000005'; Sev='CAT II'; Cci='CCI-000172'; Dev='' }
    )

    $current = @{}

    try {
        $raw = & auditpol /get /category:* /r 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { throw "auditpol /get returned no data (exit=$LASTEXITCODE)." }
        $parsed = $raw | Where-Object { $_ -and $_ -notmatch '^Machine Name,' } | ConvertFrom-Csv -Header 'Machine','Target','Subcategory','Guid','Setting','Setting2','Setting3'
        foreach ($p in $parsed) {
            if ($p.Guid) { $current[$p.Guid.Trim().ToLower()] = $p.Setting.Trim() }
        }
        Write-CmmcLog -Context $ctx -Message ("parsed {0} audit subcategories from auditpol." -f $current.Count) -Level INFO
    } catch {
        Write-CmmcLog -Context $ctx -Message ("Failed to read audit policy: {0}" -f $_.Exception.Message) -Level ERROR
    }

    foreach ($r in $required) {
        $key = $r.Guid.ToLower()
        $actual = if ($current.ContainsKey($key)) { $current[$key] } else { '' }

        $expParts = @()
        if ($r.Success) { $expParts += 'Success' }
        if ($r.Failure) { $expParts += 'Failure' }
        $expected = ($expParts -join ' and ')
        if (-not $expected) { $expected = 'No Auditing' }

        $okSuccess = (-not $r.Success) -or ($actual -match 'Success|성공')
        $okFailure = (-not $r.Failure) -or ($actual -match 'Failure|실패')
        if (-not $current.ContainsKey($key)) {
            $status = 'FAIL'
            $actualText = ("Not found (subcategory GUID {0} absent on this OS build)" -f $r.Guid)
        } elseif ($okSuccess -and $okFailure) {
            $status = 'PASS'
            $actualText = $actual
        } else {
            $status = 'FAIL'
            $actualText = $actual
        }
        Add-CmmcResult -Context $ctx -Item ("{0} :: {1}" -f $r.Group, $r.Sub) -Control $r.Control `
            -Expected $expected -Actual $actualText -Status $status `
            -Detail 'DoD ODP audit event type required by AU.L2-3.3.1/.2.' `
            -StigId $r.StigId -Severity $r.Sev -Cci $r.Cci -Deviation $r.Dev
    }

    if ($Mode -eq 'Enforce') {
        if (-not (Test-CmmcAdmin)) {
            Add-CmmcResult -Context $ctx -Item 'Enforce prerequisite' -Control 'AU.L2-3.3.1' `
                -Expected 'Administrator' -Actual 'Non-administrator' -Status 'FAIL' `
                -Detail 'Enforce requires an elevated PowerShell session. No changes applied.'
        } else {

            if (-not (Test-Path $ctx.BackupDir)) { New-Item -ItemType Directory -Path $ctx.BackupDir -Force | Out-Null }
            $bkFile = Join-Path $ctx.BackupDir (("04_AuditPolicy_{0}.auditpol-backup.csv") -f (Get-CmmcTimestamp -ForFile))
            try {
                & auditpol /backup /file:"$bkFile" 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0 -and (Test-Path $bkFile)) {
                    Write-CmmcLog -Context $ctx -Message ("audit policy backed up to {0}. Rollback: auditpol /restore /file:`"{0}`"" -f $bkFile) -Level WARN
                    Add-CmmcResult -Context $ctx -Item 'Audit policy backup' -Control 'AU.L2-3.3.1' `
                        -Expected 'Backup created' -Actual $bkFile -Status 'INFO' `
                        -Detail ("Rollback: auditpol /restore /file:`"{0}`"" -f $bkFile)
                } else {
                    Write-CmmcLog -Context $ctx -Message 'auditpol /backup did not produce a file; proceeding with caution.' -Level WARN
                }
            } catch {
                Write-CmmcLog -Context $ctx -Message ("Backup failed: {0}" -f $_.Exception.Message) -Level ERROR
            }

            foreach ($r in $required) {
                $succ = if ($r.Success) { 'enable' } else { 'disable' }
                $fail = if ($r.Failure) { 'enable' } else { 'disable' }

                if (-not $current.ContainsKey($r.Guid.ToLower())) {
                    Add-CmmcResult -Context $ctx -Item ("{0} :: {1}" -f $r.Group, $r.Sub) -Control $r.Control `
                        -Expected 'Audit enabled' -Actual ("subcategory GUID {0} absent on this OS build" -f $r.Guid) -Status 'FAIL' `
                        -Detail 'auditpol /set skipped: GUID not present on this OS.' `
                        -StigId $r.StigId -Severity $r.Sev -Cci $r.Cci -Deviation $r.Dev
                    continue
                }
                try {
                    & auditpol /set /subcategory:"$($r.Guid)" /success:$succ /failure:$fail 2>$null | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        $expParts = @()
                        if ($r.Success) { $expParts += 'Success' }
                        if ($r.Failure) { $expParts += 'Failure' }
                        $expected = ($expParts -join ' and '); if (-not $expected) { $expected = 'No Auditing' }
                        Add-CmmcResult -Context $ctx -Item ("{0} :: {1}" -f $r.Group, $r.Sub) -Control $r.Control `
                            -Expected $expected -Actual ("success:{0} failure:{1}" -f $succ, $fail) -Status 'ENFORCED' `
                            -Detail ("auditpol /set applied (subcategory GUID {0})." -f $r.Guid) `
                            -StigId $r.StigId -Severity $r.Sev -Cci $r.Cci -Deviation $r.Dev
                    } else {
                        Add-CmmcResult -Context $ctx -Item ("{0} :: {1}" -f $r.Group, $r.Sub) -Control $r.Control `
                            -Expected 'Audit enabled' -Actual ("auditpol exit={0}" -f $LASTEXITCODE) -Status 'FAIL' `
                            -Detail ("auditpol /set failed for GUID {0}." -f $r.Guid) `
                            -StigId $r.StigId -Severity $r.Sev -Cci $r.Cci -Deviation $r.Dev
                    }
                } catch {
                    Write-CmmcLog -Context $ctx -Message ("Set failed for '{0}' ({1}): {2}" -f $r.Sub, $r.Guid, $_.Exception.Message) -Level ERROR
                }
            }
        }
    }
}
catch { Write-CmmcLog -Context $ctx -Message $_.Exception.Message -Level ERROR }
Complete-CmmcRun -Context $ctx -Title 'Audit Policy'
