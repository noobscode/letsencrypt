<#
.NOTES
  Version:        1.0
  Author:         Alexander A. Nordbø
  Creation Date:  21.12.2021
  Purpose/Change: Automaticly download a spesific version of lets encrypt.
                  Fixes an issue where sites do not update binding correctly after renewal.
                  This sscript will also update/create/cleanup any related scheduled tasks.
                  Run renewal of all sites with a pending renewal status.
#>

# Do not change these variables unless you know what youre doing!
$Package = "https://github.com/win-acme/win-acme/releases/download/v2.1.20.1/win-acme.v2.1.20.1185.x64.pluggable.zip"
$ExtractPath = "C:\Tools\letsencrypt\letsencrypt_automation\"
$DownloadDir = "C:\temp\letsencrypt_automation\"
$LogDir = "C:\Tools\letsencrypt\letsencrypt_automation_logs"

# Get the time and date for logging purposes
$timestamp = Get-Date -Format FileDateTime

Function LogWrite
{
   Param ([string]$logstring)

   Add-content "$LogDir\$timestamp-automation_transcript.txt" -value $logstring
   Write-Host $logstring
}

# Loop that runs until we have exclusive write access to $LockFile
$LockFile = "C:\Temp\run.lock"
$sleeptime = 60

If (!(Test-Path -PathType Container -Path $LockFile)) {
  New-Item -ItemType Directory -Force -Path C:\Temp | Out-Null
}


While(Test-Path -Path $lockfile)
{
    Write-Host "! [WARNING] LOCKFILE Found!"
    Write-Host "This means this task is being used by another process"
    Write-Host "Wait for file to be deleted/released"
    Write-Host "Sleeping for $sleeptime seconds (feel free to cancel script)"
    Start-Sleep $sleeptime -Verbose
}

# Active LOCKFILE preventing this script from running in another process
New-item -Path $lockfile | Out-Null

try {
  Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
  Import-Module IISAdministration -ErrorAction SilentlyContinue | Out-Null
}
catch {
  LogWrite "- [ERROR] Unable to load powershell libraries"
  exit
}

If (!(test-path $ExtractPath)) {
  New-Item -ItemType Directory -Force -Path $ExtractPath | Out-Null
}
else {
  Remove-Item -LiteralPath $ExtractPath -Force -Recurse | Out-Null
  New-Item -ItemType Directory -Force -Path $ExtractPath | Out-Null
}

If (!(test-path $DownloadDir)) {
  New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null
}

If (!(test-path $LogDir)) {
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

# Download, extract and replace current version
try {
  $Url = $Package
  LogWrite "+ [INFO] Downloading Lets Encrypt from:"
  LogWrite "+ [Download URL] $Url"
  $DownloadZipFile = $DownloadDir + $(Split-Path -Path $Url -Leaf)
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $Url -OutFile $DownloadZipFile
  $ExtractShell = New-Object -ComObject Shell.Application 
  $ExtractFiles = $ExtractShell.Namespace($DownloadZipFile).Items() 
  $ExtractShell.NameSpace($ExtractPath).CopyHere($ExtractFiles)
  Remove-Item -Path $DownloadZipFile -Confirm:$false -Force | Out-Null
}
catch {
  LogWrite "- [ERROR] Unable to Download/Update Lets Encrypt Packages from $Url"
  exit 1
}

# Update default settings for win-acme to redirect logs
LogWrite "+ [INFO] Update Lets Encrypt Configuration to fit our needs"
$configFiles = Get-ChildItem -File -Path "$ExtractPath\*" -include settings_default.json
foreach ($file in $configFiles) { 
  (Get-Content $file.PSPath) | Foreach-Object { 
    $_ -replace '"LogPath": null,', '"LogPath": "C:\\Tools\\letsencrypt\\letsencrypt_automation_logs",' 
  } | Set-Content $file.PSPath
}

# Get Misconfigured IIS Sites
LogWrite "+ [INFO] Checking for IIS Sites with assigned certificates and validate configuration...."
$SSLSites = Get-ChildItem IIS:SSLBindings | Select-Object -Property *
$BrokenSites = @()

Foreach ($Site in $SSLSites) {
  $Store = $Site.Store
  $Property = Get-ChildItem CERT:LocalMachine/$Store | Select-Object -Property DnsNameList, FriendlyName, Issuer | `
    Where-Object {
    $_.DnsNameList.Punycode -eq $Site.Host -and `
      $_.Issuer -eq "CN=R3, O=Let's Encrypt, C=US" -and `
      $_.FriendlyName -like '*Manual*' `
  }

  # Create an array list of sites that needs fixing
  Foreach ($i in $Property.DnsNameList.Punycode) {
    $BrokenSites += $i
  }
}

if ($BrokenSites -gt 0) {
  LogWrite "+ [WARN] Found Sites with SSL Certificate Issues."
  LogWrite "+ [WARN] List of Sites with SSL issues:"
  LogWrite "$BrokenSites"
} else {
  LogWrite "+ [OK] No Sites with SSL Certificate Issues Found."
}

# Clear out variables just to be safe
$Site = $null

foreach ($Site in $BrokenSites) {
  LogWrite "+ [INFO] Fixing $Site"
    
  # Make sure the site is working before making changes
  LogWrite "+ [INFO] Validating connection and SSL for $Site"
  $url = "https://$Site/" 
  $req = [Net.HttpWebRequest]::Create($url)
  try { 
    $req.GetResponse() | Out-Null
    $SiteStatus = $true
    LogWrite "+ [OK] Validation Passed: $Site"
  }
  catch { 
    $SiteStatus = $false
    LogWrite "- [ERROR] Validation Failed: $Site" 
    LogWrite "- [ERROR] Possible SSL or binding Error for $Site. Investigation required! (Skipping site)"
  }

  if ($true -eq $SiteStatus) {
    $SiteProperty = Get-ChildItem IIS:SSLBindings | Select-Object -Property * | Where-Object { $_.Host -eq $Site }
    $CertStore = $SiteProperty.Store
    $SiteName = $SiteProperty.Sites.Value
    $SiteId = (Get-IISSite $SiteName).ID
    
    try {
      # Remove IIS binding
      LogWrite "+ [INFO] Removing SSL Binding for $Site"
      Get-ChildItem IIS:SSLBindings | Select-Object -Property * | Where-Object { $_.Host -eq $Site } | Remove-Item -Force -Confirm:$false | Out-Null

      # Delete Certificate from Store
      LogWrite "+ [INFO] Deleting all certificates with Common Name matching $Site"
      Get-ChildItem Cert:\LocalMachine\$CertStore | Select-Object -Property * | Where-Object { $_.Subject -eq "CN=" + "$Site" } | Remove-Item -Force -Confirm:$false | Out-Null

      # Clean up letsencrypt renewal files
      LogWrite "+ [INFO] Cleaning up .renewal.json files for $Site"
      (Get-ChildItem -Path 'C:\ProgramData\win-acme\acme-v02.api.letsencrypt.org\*' | Select-String -Pattern $Site | Select-Object -ExpandProperty path -Unique) | ForEach-Object { Remove-Item -Force -LiteralPath $_ } | Out-Null

      # Request new ssl certificate
      LogWrite "+ [INFO] Requesting new certificate for $Site"
      Start-Process -FilePath "$ExtractPath\wacs.exe" -WorkingDirectory "$ExtractPath" -ArgumentList "--source iis", "--commonname $Site", "--host $Site", "--siteid $SiteId", "--verbose" -Wait

      # Create New SSL Binding
      LogWrite "+ [INFO] Collecting the new Thumbprint for the newly generated certificate"
      $NewCertThumbprint = (Get-ChildItem Cert:\LocalMachine\$CertStore | Select-Object -Property * | Where-Object { $_.Subject -eq "CN=" + "$Site" }).Thumbprint
      LogWrite "+ [INFO] New Thumbprint: $NewCertThumbprint"
      LogWrite "+ [INFO] Append Certificate to SSL Binding for $Site"
      (Get-WebBinding -Name $SiteName -Port 443 -Protocol "https").AddSslCertificate($NewCertThumbprint, $CertStore) | Out-Null
    }
    catch {
      LogWrite "- [ERROR] Unable to fix the following site: $Site"
      LogWrite "- [ERROR] $_"
    }

    # Retest the site and make sure we didn't break anything
    LogWrite "+ [INFO] Re-Validating connection and SSL for $Site after correcting site..."
    $url = "https://$Site/" 
    $req = [Net.HttpWebRequest]::Create($url)
    try { 
      $req.GetResponse() | Out-Null
      $SiteStatus = $true
      LogWrite "+ [OK] Validation Passed: $Site"
    }
    catch { 
      $SiteStatus = $false
      LogWrite "- [ERROR] Validation Failed: $Site" 
      LogWrite "- [ERROR] Possible SSL or binding Error for $Site. Investigation required!"
      LogWrite "- [ERROR] Previous test before making changes prooved that the site was working, my bad."
    }
  }
}

# Renew Certificates with pending renewal
LogWrite "+ [INFO] Renew Existing Certificates with pending renewal status"
Start-Process -FilePath "$ExtractPath\wacs.exe" -WorkingDirectory "$ExtractPath" -ArgumentList "--renew", "--verbose" -Wait

# Disable all previous/old scheduled task for letsencrypt and create new one based on latest version.
LogWrite "+ [INFO] Clean up scheduled tasks and update them to make sure we are compliant with the selected version."
Get-ScheduledTask | Select-Object -Property * | Where-Object { $_.Description -like '*Lets Encrypt*' -or $_.Description -like '*ACME*' } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue } | Out-Null
Start-Process -FilePath "$ExtractPath\wacs.exe" -WorkingDirectory "$ExtractPath" -ArgumentList "--setuptaskscheduler" -Wait

# Cleanup download directory
LogWrite "+ [INFO] Start Clean Up...."

# Remove expired certificates
LogWrite "+ [INFO] Removing Expired Certificates From WebHosting Store"
$Certs = Get-ChildItem "Cert:\LocalMachine\WebHosting" -Recurse
Foreach($Cert in $Certs) {
  # If The objects property "NotAfter" is older than the current time, delete
  If($Cert.NotAfter -lt (Get-Date)) {
      $Cert | Remove-Item | Out-Null
  }
}

# Remove Duplicate certificates, keep newest
LogWrite "+ [INFO] Removing duplicate certificates (Deleted certificates will be listed bellow)"
$ht = @{}
Get-ChildItem -Recurse Cert:\LocalMachine\WebHosting |
    Where-Object { $_.Issuer -like "*CN=R3, O=Let's Encrypt, C=US*"  } |
    ForEach-Object {
        $subject = $_.Subject
        if (!$ht.ContainsKey($subject)) {
            $ht[$subject] = @{}
        }
        $ht[$subject]["$($_.Thumbprint)"] = $_
    }

$ht.Keys | ForEach-Object {
    $dupes = ($ht[$_] | Where-Object { $_.Count -gt 1 })
    if ($dupes) {
        $dupes.GetEnumerator() |
            Sort-Object [DateTime]"${Value.GetDateTimeString()}" -Descending |
            Select-Object -ExpandProperty Value -Skip 1 |
            ForEach-Object {
                if (Test-Path $_.PSPath) {
                    Remove-Item -Path $_.PSPath -DeleteKey | Out-Null
                    $_
                }
            }
    }
}

LogWrite "+ [INFO] DONE!"
Write-Host "Let's Encrypt Log Directory: $LogDir\acme-v02.api.letsencrypt.org"
Write-Host "Output from this script is logged to: $LogDir\$timestamp-automation_transcript.txt"

# Cleanup lock file
Remove-Item $lockfile –Force | Out-Null
