# letsencrypt
Run Powershell as Administrator and run command:
```powershell
$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/letsencrypt/main/runbook.ps1;Invoke-Expression $($s.Content)
```
The request was aborted: Could not create SSL/TLS Secure Channel
Use This command:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/letsencrypt/main/runbook.ps1;Invoke-Expression $($s.Content)
```
