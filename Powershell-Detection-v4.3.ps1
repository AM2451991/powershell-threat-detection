# =================================================================
# SOC LAB - POWERSHELL DETECTION v4.3
# Purpose: Detect suspicious PowerShell command-line activity
# Source: Windows Security Event ID 4688
# =================================================================


Write-Host ""
Write-Host "=== SOC LAB: POWERSHELL DETECTION v4.3 ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Checking recent PowerShell proces creation events..."
Write-Host ""


$events = Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id      = 4688
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue


if (-not $events) {
    Write-Host "No process creation events found in the last 24 hours."
    exit
}

$alerts = 0

foreach ($event in $events) {

   try {
       [xml]$xml = $event.ToXml()

       $data = @{}

       foreach ($item in $xml.Event.EventData.Data) {
          $data[$item.Name] = $item.'#text'
       }

       $processName = $data["NewProcessName"]
       $commandLine = $data["CommandLine"]
       $user        = $data["SubjectUserName"]
       $processId   = $data["NewProcessId"]
       $parent      = $data["ParentProcessName"]


       # -------------------------------------------------------------
       # Only investigate PowerShell
       # -------------------------------------------------------------


       if ($processName -notmatch '(?i)powershell\.exe$') {
           continue
       }

       if ([string]::IsNullOrWhiteSpace($commandLine)) {
           continue
       }


       # -------------------------------------------------------------
       # Ignore our known SOC lab detector execution
       # -------------------------------------------------------------


       if ($commandLine -match '(?i)C:\\SOC-Lab\\Scripts\\Powershell-Detection(?:-v\d+(?:\.\d+)?)?\.ps1') {
           continue
       }


       $indicator      = $null
       $severity       = $null
       $reason         = $null
       $recommendation = $null
       $decodedCommand = $null
       $mitreTechnique = $null
       $mitreId        = $null


       # -------------------------------------------------------------
       # Indicator 1: EncodedCommand
       # -------------------------------------------------------------


       if ($commandLine -match '(?i)-EncodedCommand\s+([A-Za-z0-9+/=]+)') {

           $indicator = "-EncodedCommand"
           $severity  = "High"

           $mitreTechnique = "Obfuscated/Compressed Files or Information"
           $mitreId = "T1027"

           $reason = "PowerShell command was supplied in encoded form."

           $recommendation = "Decode the command and investigate the parent process and user context."

           try {
               $encoded = $matches[1]

               $bytes = [convert]::FromBase64String($encoded)

               $decodedCommand = [Text.Encoding]::Unicode.GetString($bytes)

           }
           catch {

               $decodedCommand = "Unable to decode command."

           }
       }


       # -------------------------------------------------------------
       # Indicator 2: ExecutionPolicy Bypass
       # -------------------------------------------------------------


       elseif ($commandLine -match '(?i)-ExecutionPolicy\s+Bypass') {

           $indicator = "-ExecutionPolicy Bypass"
           $severity  = "Medium"

           $mitreTechnique = "Command and Scripting Interpreter: PowerShell"
           $mitreId = "T1059.001"

           $reason = "PowerShell execution policy was bypassed."

           $recommendation = "Determine why the policy was bypassed and verify the script being executed."
       }


       # -------------------------------------------------------------
       # Indicator 3: Invoke-Expression / IEX
       # -------------------------------------------------------------


       elseif ($commandLine -match '(?i)\bIEX\b|\bInvoke-Expression\b') {

           $indicator = "Invoke-Expression / IEX"
           $severity  = "High"

           $mitreTechnique = "Command and Scripting Interpreter: PowerShell"
           $mitreId = "T1059.001"

           $reason = "PowerShell was instructed to dynamically execute a command or script."

           $recommendation = "Inspect the complete command and determine the source of the executed content."
       }


       # -------------------------------------------------------------
       # Indicator 4: DownloadString
       # -------------------------------------------------------------


       elseif ($commandLine -match '(?i)DownloadString') {

           $indicator = "DownloadString"
           $severity  = "High"

           $mitreTechnique = "Ingress Tool Transfer"
           $mitreId = "T1105"

           $reason = "PowerShell command contains a mechanism commonly used to retrieve remote content."

           $recommendation = "Investigate the destination URL and determine whether downloaded content was executed."
       }


       # -------------------------------------------------------------
       # Indicator 5: FromBase64String
       # -------------------------------------------------------------


       elseif ($commandLine -match '(?i)FromBase64String') {

           $indicator = "FromBase64String"
           $severity  = "High"

           $mitreTechnique = "Deobfuscate/Decode Files or Information"
           $mitreId = "T1140"

           $reason = "PowerShell command contains Base64 decoding functionality."

           $recommendation = "Decode the embedded content and investigate its purpose."
       }


       # -------------------------------------------------------------
       # Indicator 6: Hidden window
       # -------------------------------------------------------------


       elseif ($commandLine -match '(?i)-WindowStyle\s+Hidden') {

           $indicator = "-WindowStyle Hidden"
           $severity  = "Medium"

           $mitreTechnique = "Hide Artifacts"
           $mitreId = "T1564"

           $reason = "PowerShell was launched with a hidden window."

           $recommendation = "Investigate the parent process and full command line for potential stealth execution."
       }


       # -------------------------------------------------------------
       # Generate SOC alert
       # -------------------------------------------------------------


       if ($indicator) {

           $alerts++

           # Generate unique SOC alert ID
           $alertId = "SOC-PS-{0}-{1:D3}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), $alerts

           Write-Host "---------------------------------------"
           Write-Host "SOC ALERT" -ForegroundColor Red
           Write-Host "---------------------------------------"


           Write-Host "Alert ID       : $alertId"
           Write-Host "Time           : $($event.TimeCreated)"
           Write-Host "User           : $user"
           Write-Host "Process ID     : $processId"
           Write-Host "Process        : $processName"
           Write-Host "Parent Process : $parent"
           Write-Host "Severity       : $severity"
           Write-Host "Indicator      : $indicator"
           Write-Host "MITRE ATTACK   : $mitreId - $mitreTechnique"


           Write-Host ""
           Write-Host "Reason:"
           Write-Host $reason

           Write-Host ""
           Write-Host "Analyst Recommendation:"
           Write-Host $recommendation

           if ($decodedCommand) {
               Write-Host ""
               Write-Host "Decoded Command:" -ForegroundColor Yellow
               Write-Host $decodedCommand
           }

           Write-Host ""
           Write-Host "Command Line:"
           Write-Host $commandLine

           Write-Host ""
       }
    }
    catch {
        continue
    }
}

Write-Host "---------------------------------------"

if ($alerts -eq 0) {
    Write-Host "No suspicious PowerShell activity detected."
}
else {
      Write-Host "Total SOC alerts generated: $alerts" -ForegroundColor Yellow
}

Write-Host "---------------------------------------"