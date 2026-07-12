param(
    [string]$Mode = 'Check',
    [switch]$Quiet,
    [Alias('Usage','h')][switch]$Help
)
. "$PSScriptRoot\_CmmcCommon.ps1"
$script:CmmcMeta = @{
    Name     = '06_FipsMode'
    Purpose  = 'Windows FIPS 알고리즘 정책(FIPS 모드) 점검 및 강제 적용.'
    Modes    = 'Check, Enforce'
    Scope    = 'SC.L2-3.13.11 / WN11-SO-000230'
    Examples = @('.\06_FipsMode.ps1 -Mode Check', '.\06_FipsMode.ps1 -Help')
}
if ($Help) { Show-CmmcUsage $script:CmmcMeta; exit 0 }
$resolvedMode = Resolve-CmmcMode $Mode
if (-not $resolvedMode) { Write-Host '[ERROR] -Mode must be Check or Enforce (abbrev c/e ok).' -ForegroundColor Red; Show-CmmcUsage $script:CmmcMeta; exit 2 }
$Mode = $resolvedMode
$ctx = Initialize-CmmcRun -ScriptId '06_FipsMode' -Mode $Mode -Quiet:$Quiet
try {

    $regPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
    $regName = 'Enabled'

    $current = $null
    try {
        $current = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
    } catch {
        $current = $null
    }
    $actual = if ($null -eq $current) { '(not set)' } else { [string]$current }
    $status = if ($current -eq 1) { 'PASS' } else { 'FAIL' }

    Add-CmmcResult -Context $ctx -Item 'FIPS Algorithm Policy (Enabled)' -Control 'SC.L2-3.13.11' `
        -Expected '1' -Actual $actual -Status $status `
        -StigId 'WN11-SO-000230' -Severity 'CAT II' -Cci 'CCI-002450' `
        -Detail 'FIPS mode forces use of CMVP-validated cryptography (e.g., BitLocker, TLS). Reference CMVP certificate [CMVP#].'

    if ($Mode -eq 'Enforce') {
        Set-CmmcRegistry -Context $ctx -Path $regPath -Name $regName -Value 1 -Type DWord

        Add-CmmcResult -Context $ctx -Item 'FIPS Algorithm Policy (Enabled)' -Control 'SC.L2-3.13.11' `
            -Expected '1' -Actual '1' -Status 'ENFORCED' `
            -StigId 'WN11-SO-000230' -Severity 'CAT II' -Cci 'CCI-002450' `
            -Detail 'Set FipsAlgorithmPolicy\Enabled = 1. A reboot may be required for the policy to take full effect. CMVP-validated cryptography (e.g., BitLocker, TLS); reference CMVP certificate [CMVP#].'
    }
}
catch { Write-CmmcLog -Context $ctx -Message $_.Exception.Message -Level ERROR }
Complete-CmmcRun -Context $ctx -Title 'FIPS Mode'
