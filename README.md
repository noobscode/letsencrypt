# Let's Encrypt IIS (WIN-ACME)
The following will happen when you run the script:
1. Download a spesific version of WIN-ACME. Download link provided as variable in top of the script, modify this to change version.
2. Check for any sites with [Manual] in friendly name. This might cause issues when renewing and you will lose the ssl cert in binding.
3. Do an ssl check against sites with [Manual] certificates.
4. Remove binding from site
5. Delete all certificates in WebHosting Certificate Store mtching the common name for that spesific site.
6. Delete all .renewal.json files for that site/common name.
7. Request new certificate for that site/common name.
8. Create new binding with the newly generated certificate.
9. Re-validate site after binding is set to make sure the site didn't break during the process.
10. Renew existing certificates with a pending renewal.
11. Disable all old scheduled tasks related to let's encrypt and or ACME.
12. Create new scheduled task that is compliant and pointing to the current version of win-acme.
13. Remove all expired certificates from the WebHosting Certificate Store.
14. Remove any duplicate Certificates from WebHosting Certificate Store (Matching CN). 


# How to run
- Run Powershell as Administrator and run command:
```powershell
$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/letsencrypt/main/runbook.ps1;Invoke-Expression $($s.Content)
```
## In some cases you might run into...
**The request was aborted: Could not create SSL/TLS Secure Channel.**
- Use This command:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/letsencrypt/main/runbook.ps1;Invoke-Expression $($s.Content)
```
**The response content cannot be parsed because the Internet Explorer engine is not available**
- Use This command:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/letsencrypt/main/runbook.ps1 -UseBasicParsing;Invoke-Expression $($s.Content)
```
