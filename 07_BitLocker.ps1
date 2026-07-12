param(
    [string]$Mode = 'Check',
    [switch]$Quiet,
    [Alias('Usage','h')][switch]$Help
)
. "$PSScriptRoot\_CmmcCommon.ps1"
$script:CmmcMeta = @{
    Name     = '07_BitLocker'
    Purpose  = 'TPM+PIN 사전 부팅 인증과 FIPS 승인 암호를 사용하는 BitLocker로 OS 볼륨 전체 디스크 암호화를 점검/적용.'
    Modes    = 'Check, Enforce'
    Scope    = 'SC.L2-3.13.11, SC.L2-3.13.16 / WN11-00-000030,031,032'
    Examples = @('.\07_BitLocker.ps1 -Mode Check', '.\07_BitLocker.ps1 -Help')
}
if ($Help) { Show-CmmcUsage $script:CmmcMeta; exit 0 }
$resolvedMode = Resolve-CmmcMode $Mode
if (-not $resolvedMode) { Write-Host '[ERROR] -Mode must be Check or Enforce (abbrev c/e ok).' -ForegroundColor Red; Show-CmmcUsage $script:CmmcMeta; exit 2 }
$Mode = $resolvedMode
$ctx = Initialize-CmmcRun -ScriptId '07_BitLocker' -Mode $Mode -Quiet:$Quiet
try {

    $fvePath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

    $blAvailable = $null -ne (Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue)
    if (-not $blAvailable) {

        Add-CmmcResult -Context $ctx -Item 'BitLocker module availability' -Control 'SC.L2-3.13.16' -Expected 'Get-BitLockerVolume present' -Actual 'cmdlet not found' -Status INFO -Detail 'BitLocker cmdlets/module unavailable (edition/feature). Verify OS-volume encryption manually with manage-bde -status C:.' -StigId 'WN11-00-000030' -Severity 'CAT I' -Cci 'CCI-002475'
    } else {
        try {

            $osDrive = "$env:SystemDrive"
            $vol = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop

            $ps = "$($vol.ProtectionStatus)"
            $status = if ($ps -eq 'On') { 'PASS' } else { 'FAIL' }

            Add-CmmcResult -Context $ctx -Item 'OS volume ProtectionStatus' -Control 'SC.L2-3.13.16' -Expected 'On' -Actual $ps -Status $status -Detail ("BitLocker protection state for {0}." -f $osDrive) -StigId 'WN11-00-000030' -Severity 'CAT I' -Cci 'CCI-002475'

            $em = "$($vol.EncryptionMethod)"
            $status = if ($em -like 'XtsAes*' -or $em -like 'XTS-AES*') { 'PASS' } else { 'FAIL' }

            Add-CmmcResult -Context $ctx -Item 'OS volume EncryptionMethod' -Control 'SC.L2-3.13.11' -Expected 'XTS-AES (XtsAes128/XtsAes256)' -Actual $em -Status $status -Detail 'XTS-AES is the FIPS-validated cipher for data-at-rest on the OS volume.' -StigId '[확인필요]' -Severity '' -Cci ''

            $kpTypes = @()
            if ($vol.KeyProtector) { $kpTypes = @($vol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" }) }
            $hasTpmPin = ($kpTypes -contains 'TpmPin')
            $status = if ($hasTpmPin) { 'PASS' } else { 'FAIL' }

            Add-CmmcResult -Context $ctx -Item 'OS volume key protector (TPM+PIN)' -Control 'SC.L2-3.13.16' -Expected 'TpmPin present' -Actual (($kpTypes -join ', ')) -Status $status -Detail 'Pre-boot TPM+PIN binds decryption to the device and a user-supplied PIN.' -StigId 'WN11-00-000031' -Severity 'CAT I' -Cci 'CCI-002476'
        } catch {

            Add-CmmcResult -Context $ctx -Item 'OS volume BitLocker state' -Control 'SC.L2-3.13.16' -Expected 'queryable' -Actual 'query failed' -Status N/A -Detail ("Get-BitLockerVolume failed: {0}" -f $_.Exception.Message) -StigId 'WN11-00-000030' -Severity 'CAT I' -Cci 'CCI-002475'
            Write-CmmcLog -Context $ctx -Message ("Get-BitLockerVolume check failed: {0}" -f $_.Exception.Message) -Level ERROR
        }
    }

    try {
        $cur = $null
        if (Test-Path $fvePath) {
            $p = Get-ItemProperty -Path $fvePath -Name 'UseAdvancedStartup' -ErrorAction SilentlyContinue
            if ($p) { $cur = $p.UseAdvancedStartup }
        }
        $status = if ("$cur" -eq '1') { 'PASS' } else { 'FAIL' }

        Add-CmmcResult -Context $ctx -Item 'FVE UseAdvancedStartup' -Control 'SC.L2-3.13.16' -Expected '1' -Actual "$cur" -Status $status -Detail 'HKLM Policies\Microsoft\FVE; require additional authentication at startup.' -StigId 'WN11-00-000031' -Severity 'CAT I' -Cci 'CCI-002476'
    } catch { Write-CmmcLog -Context $ctx -Message ("UseAdvancedStartup check failed: {0}" -f $_.Exception.Message) -Level ERROR }

    try {
        $cur = $null
        if (Test-Path $fvePath) {
            $p = Get-ItemProperty -Path $fvePath -Name 'UseTPMPIN' -ErrorAction SilentlyContinue
            if ($p) { $cur = $p.UseTPMPIN }
        }
        $status = if ("$cur" -eq '1') { 'PASS' } else { 'FAIL' }
        $det = 'HKLM Policies\Microsoft\FVE; value 1 = require a TPM startup PIN (0=disallow, 2=allow).'
        if ("$cur" -eq '2') { $det += " 현재 2(allow, 네트워크 언락 시나리오용) → 에어갭 STIG 기대=1(require)." }

        Add-CmmcResult -Context $ctx -Item 'FVE UseTPMPIN' -Control 'SC.L2-3.13.16' -Expected '1 (require startup PIN with TPM)' -Actual "$cur" -Status $status -Detail $det -StigId 'WN11-00-000031' -Severity 'CAT I' -Cci 'CCI-002476'
    } catch { Write-CmmcLog -Context $ctx -Message ("UseTPMPIN check failed: {0}" -f $_.Exception.Message) -Level ERROR }

    try {
        $cur = $null
        if (Test-Path $fvePath) {
            $p = Get-ItemProperty -Path $fvePath -Name 'UseTPMKeyPIN' -ErrorAction SilentlyContinue
            if ($p) { $cur = $p.UseTPMKeyPIN }
        }
        $status = if ("$cur" -eq '1') { 'PASS' } else { 'FAIL' }
        $det = 'HKLM Policies\Microsoft\FVE; value 1 = require startup key and PIN with TPM (0=disallow, 2=allow).'
        if ("$cur" -eq '2') { $det += " 현재 2(allow) → 에어갭 STIG 기대=1(require)." }

        Add-CmmcResult -Context $ctx -Item 'FVE UseTPMKeyPIN' -Control 'SC.L2-3.13.16' -Expected '1 (require startup key+PIN with TPM)' -Actual "$cur" -Status $status -Detail $det -StigId 'WN11-00-000031' -Severity 'CAT I' -Cci 'CCI-002476'
    } catch { Write-CmmcLog -Context $ctx -Message ("UseTPMKeyPIN check failed: {0}" -f $_.Exception.Message) -Level ERROR }

    try {
        $cur = $null
        if (Test-Path $fvePath) {
            $p = Get-ItemProperty -Path $fvePath -Name 'MinimumPIN' -ErrorAction SilentlyContinue
            if ($p) { $cur = $p.MinimumPIN }
        }
        $cn = $null; $okNum = [int]::TryParse(("" + $cur), [ref]$cn)
        $status = if ($okNum -and $cn -ge 6) { 'PASS' } else { 'FAIL' }

        Add-CmmcResult -Context $ctx -Item 'FVE MinimumPIN' -Control 'SC.L2-3.13.16' -Expected '>=6' -Actual "$cur" -Status $status -Detail 'HKLM Policies\Microsoft\FVE; minimum pre-boot PIN length must be 6 or greater.' -StigId 'WN11-00-000032' -Severity 'CAT II' -Cci 'CCI-000804'
    } catch { Write-CmmcLog -Context $ctx -Message ("MinimumPIN check failed: {0}" -f $_.Exception.Message) -Level ERROR }

    if ($Mode -eq 'Enforce') {

        try {
            Set-CmmcRegistry -Context $ctx -Path $fvePath -Name 'UseAdvancedStartup' -Value 1 -Type DWord

            Add-CmmcResult -Context $ctx -Item 'FVE UseAdvancedStartup' -Control 'SC.L2-3.13.16' -Expected '1' -Actual '1' -Status ENFORCED -Detail 'Set HKLM Policies\Microsoft\FVE UseAdvancedStartup=1 (DWord). Policy only; no protector/volume change.' -StigId 'WN11-00-000031' -Severity 'CAT I' -Cci 'CCI-002476'
        } catch { Write-CmmcLog -Context $ctx -Message ("Enforce UseAdvancedStartup failed: {0}" -f $_.Exception.Message) -Level ERROR }

        try {
            Set-CmmcRegistry -Context $ctx -Path $fvePath -Name 'UseTPMPIN' -Value 1 -Type DWord

            Add-CmmcResult -Context $ctx -Item 'FVE UseTPMPIN' -Control 'SC.L2-3.13.16' -Expected '1' -Actual '1' -Status ENFORCED -Detail 'Set HKLM Policies\Microsoft\FVE UseTPMPIN=1 (DWord) = require TPM startup PIN (was 2=allow; air-gapped). Policy only; no protector change.' -StigId 'WN11-00-000031' -Severity 'CAT I' -Cci 'CCI-002476'
        } catch { Write-CmmcLog -Context $ctx -Message ("Enforce UseTPMPIN failed: {0}" -f $_.Exception.Message) -Level ERROR }

        try {
            Set-CmmcRegistry -Context $ctx -Path $fvePath -Name 'UseTPMKeyPIN' -Value 1 -Type DWord

            Add-CmmcResult -Context $ctx -Item 'FVE UseTPMKeyPIN' -Control 'SC.L2-3.13.16' -Expected '1' -Actual '1' -Status ENFORCED -Detail 'Set HKLM Policies\Microsoft\FVE UseTPMKeyPIN=1 (DWord) = require startup key+PIN (was 2=allow; air-gapped). Policy only; no protector change.' -StigId 'WN11-00-000031' -Severity 'CAT I' -Cci 'CCI-002476'
        } catch { Write-CmmcLog -Context $ctx -Message ("Enforce UseTPMKeyPIN failed: {0}" -f $_.Exception.Message) -Level ERROR }

        try {
            Set-CmmcRegistry -Context $ctx -Path $fvePath -Name 'MinimumPIN' -Value 6 -Type DWord

            Add-CmmcResult -Context $ctx -Item 'FVE MinimumPIN' -Control 'SC.L2-3.13.16' -Expected '6' -Actual '6' -Status ENFORCED -Detail 'Set HKLM Policies\Microsoft\FVE MinimumPIN=6 (DWord). Minimum pre-boot PIN length. Policy only; existing PINs unchanged.' -StigId 'WN11-00-000032' -Severity 'CAT II' -Cci 'CCI-000804'
        } catch { Write-CmmcLog -Context $ctx -Message ("Enforce MinimumPIN failed: {0}" -f $_.Exception.Message) -Level ERROR }

        Add-CmmcResult -Context $ctx -Item 'Encrypt OS volume + enroll TPM+PIN (manual)' -Control 'SC.L2-3.13.16' -Expected 'Encrypted with TPM+PIN, XTS-AES' -Actual 'manual step required' -Status INFO -Detail 'INTERACTIVE: run elevated  manage-bde -on C: -TPMAndPIN  (or  Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmAndPinProtector ). You will be prompted for the PIN; this script does NOT enable non-interactively.' -StigId 'WN11-00-000030' -Severity 'CAT I' -Cci 'CCI-002475'
    }
}
catch { Write-CmmcLog -Context $ctx -Message $_.Exception.Message -Level ERROR }
Complete-CmmcRun -Context $ctx -Title '07 BitLocker'
