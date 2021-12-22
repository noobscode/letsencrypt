# letsencrypt
Run Powershell as Administrator and run command:
```powershell
$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/letsencrypt/main/runbook.ps1;Invoke-Expression $($s.Content)
```
