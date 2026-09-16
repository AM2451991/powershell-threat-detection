# PowerShell Threat Detection
## Project Overview
This project is a Windows-based SOC detection lab designed to identify suspicious PowerShell activity using Windows Security process creation telemetry.
The project uses Windows Security Event ID **4688 (A new process has been created)** as the primary telemetry source. A custom PowerShell detection script analyzes recent process creation events, identifies PowerShell executions, evaluates suspicious command-line indicators, assigns severity, maps detected behavior to **MITRE ATT&CK** techniques, and generates a structured SOC-style alert.
The project was developed as a hands-on cybersecurity lab to practice security monitoring, detection engineering, alert triage, and investigation techniques in a local Windows environment.


---


## Project Objective
The objective of this project is to build and demonstrate a practical PowerShell threat-detection workflow similar to a basic SOC detection use case.
The detection focuses on identifying potentially suspicious PowerShell command-line activity, including:
- Encoded PowerShell commands
- PowerShell execution-policy bypass
- **`IEX`** / **`Invoke-Expression`**
- Remote content retrieval using **`DownloadString`**
- Base64 decoding using **`FromBase64String`**
- Hidden PowerShell windows

When suspicious activity is identified, the detector generates a SOC-style alert containing investigation context such as:
- Alert ID
- Event timestamp
- User account
- Process ID
- Process name
- Parent process
- Severity
- Suspicious indicator
- MITRE ATT&CK technique
- Reason for detection
- Analyst recommendation
- ommand line
- Decoded command, when applicable


---


## Lab Environment

## Operating System
- Windows 11
- Local virtual machine
- PowerShell 5.1

## Telemetry Source
- Windows Security Event Log
- Event ID 4688 — Process Creation

## Detection Technology
- PowerShell
- Windows Event Log
- PowerShell XML event parsing
- Regular-expression based detection logic

## Project Location
```
C:\SOC-Lab\Projects\PowerShell-Threat-Detection\
```

## Project Structure
```
PowerShell-Threat-Detection
│
├── Evidence
│   └── Detection screenshots
│
├── Powershell-Detection-v4.3.ps1
│
└── README.md
```


---


## Detection Workflow
The detection workflow follows a simplified SOC investigation process:
```
Windows Process Creation
       │
       ▼
Security Event ID 4688
       │
       ▼
Identify PowerShell
       │
       ▼
Extract Command-Line Telemetry
       │
       ▼
Check Suspicious Indicators
       │
       ├── EncodedCommand
       ├── ExecutionPolicy Bypass
       ├── IEX / Invoke-Expression
       ├── DownloadString
       ├── FromBase64String
       └── Hidden Window
       │
       ▼
Generate SOC Alert
       │
       ▼
Assign Severity
       │
       ▼
Map to MITRE ATT&CK
       │
       ▼
Provide Analyst Recommendation
```

This workflow demonstrates the core detection lifecycle of **telemetry collection → detection → alert generation → contextual analysis → investigation guidance**

## Detection Logic
The detection script analyzes Windows Security Event ID 4688 events generated within the previous 24 hours.

### 1. Event Collection
The script queries the Windows Security log for Event ID 4688:
```powershell
Get-WinEvent -FilterHashtable @{
LogName = "Security"
Id      = 4688
StartTime = (Get-Date).AddHours(-24)
}
```

Event ID 4688 provides process creation telemetry that can be used to investigate the execution of PowerShell and other processes.
The script then converts each event into XML and extracts relevant fields, including:
**`NewProcessName`**
**`CommandLine`**
**`SubjectUserName`**
**`NewProcessId`**
**`ParentProcessName`**


---


### 2. PowerShell Filtering
The detector first filters the collected process creation events so that only **`powershell.exe`** executions are investigated.
This reduces unnecessary processing of unrelated Windows processes.
Events without command-line information are also skipped because the command line is required for the indicator-based detection logic.


---


### 3. Detection Indicators
The detector evaluates the PowerShell command line against multiple suspicious indicators.


| Indicator                   | Severity | MITRE ATT&CK                                       | Detection Purpose                                                         |
| --------------------------- | -------- | -------------------------------------------------- | ------------------------------------------------------------------------- |
| `-EncodedCommand`           | High     | T1027 – Obfuscated/Compressed Files or Information | Detects encoded PowerShell commands                                       |
| `-ExecutionPolicy Bypass`   | Medium   | T1059.001 – PowerShell                             | Detects attempts to bypass PowerShell execution policy                    |
| `IEX` / `Invoke-Expression` | High     | T1059.001 – PowerShell                             | Detects dynamic execution of commands or scripts                          |
| `DownloadString`            | High     | T1105 – Ingress Tool Transfer                      | Detects PowerShell functionality commonly used to retrieve remote content |
| `FromBase64String`          | High     | T1140 – Deobfuscate/Decode Files or Information    | Detects Base64 decoding functionality                                     |
| `-WindowStyle Hidden`       | Medium   | T1564 – Hide Artifacts                             | Detects PowerShell launched with a hidden window                          |


The detection logic uses regular-expression matching to identify these indicators within the PowerShell command line.


---


### 4. Encoded Command Detection and Decoding
When **`-EncodedCommand`** is detected, the script attempts to decode the supplied Base64 value.
The script:
1. Extracts the encoded value.
2. Converts the Base64 string into bytes.
3. Decodes the bytes using Unicode encoding.
4. Displays the resulting command when decoding succeeds.
This provides an analyst with additional context during triage rather than simply reporting that an encoded command was detected.
If decoding fails, the alert reports that the command could not be decoded.


---


### 5. Severity Classification

The detector assigns severity based on the indicator identified.
**High severity indicators:**
- Encoded PowerShell commands
- `IEX` / `Invoke-Expression`
- `DownloadString`
- `FromBase64String`

**Medium severity indicators:**
- Execution Policy Bypass
- Hidden PowerShell Window

The severity represents the potential investigative priority of the behavior and does not by itself confirm that the activity is malicious.


---


### 6. SOC Alert Generation
When a suspicious indicator is identified, the detector generates a unique SOC-style alert ID.
Example format:
```
SOC-PS-YYYYMMDD-HHMMSS-001
```

Each alert contains contextual information useful for initial triage:
```
Alert ID
Time
User
Process ID
Process
Parent Process
Severity
Indicator
MITRE ATT&CK Technique
Reason
Analyst Recommendation
Command Line
Decoded Command (when applicable)
```

This allows the detection output to function as a basic analyst-oriented alert rather than simply returning a detection message.


---


### 7. Analyst Recommendations
Each detection includes an investigation recommendation based on the indicator identified.
Examples include:
- Decode and investigate encoded commands.
- Determine why execution policy was bypassed.
- Inspect the complete IEX command and identify the source of the executed content.
- Investigate remote URLs associated with `DownloadString`.
- Decode embedded Base64 content.
- Investigate the parent process and command line associated with hidden execution.

This provides an initial investigation direction for a SOC analyst.


---


### 8. False-Positive Reduction
The detector contains an exclusion for the known SOC lab detection script itself.
This prevents the detector from repeatedly identifying its own execution as suspicious PowerShell activity during testing.
The exclusion is based on the known script path configured in the detection logic:
```
C:\SOC-Lab\Scripts\Powershell-Detection\*.ps1
```

This demonstrates a basic detection-engineering concept: reducing known benign activity to minimize unnecessary alerts and improve signal quality.


---


## Detection Testing
The detection logic was tested by generating controlled PowerShell activity inside the isolated Windows SOC lab environment.
One of the successful tests involved suspicious **IEX / Invoke-Expression** activity.
The detector identified the behavior and generated a SOC alert containing:
**Alert ID**
**Timestamp**
**User**
**Process information**
**everity**
**IEX indicator**
**MITRE ATT&CK mapping**
**Detection reason**
**Analyst recommendation**
**Command line**

The resulting alert was captured as screenshot evidence in the project's `Evidence` directory.


---







**\*\*## Evidence\*\***







**\*\*The project includes screenshots demonstrating successful detection of suspicious PowerShell activity.\*\***







**\*\*### IEX Detection\*\***







**\*\*The IEX test demonstrates that the detector can identify a PowerShell command containing `IEX` / `Invoke-Expression` and generate a corresponding SOC-style alert.\*\***







**\*\*\\\*\\\*Evidence:\\\*\\\* See the `Evidence` directory.\*\***







**\*\*The screenshot demonstrates the complete detection path:\*\***







**\*\*```text\*\***



**\*\*Suspicious PowerShell Command\*\***



**\&#x20;         \*\*↓\*\***



**\*\*Windows Event ID 4688\*\***



**\&#x20;         \*\*↓\*\***



**\*\*PowerShell Detection Script\*\***



**\&#x20;         \*\*↓\*\***



**\*\*IEX Indicator Identified\*\***



**\&#x20;         \*\*↓\*\***



**\*\*High Severity Alert\*\***



**\&#x20;         \*\*↓\*\***



**\*\*MITRE ATT\\\&CK Mapping\*\***



**\&#x20;         \*\*↓\*\***



**\*\*Analyst Recommendation\*\***



**\*\*```\*\***







**\*\*The evidence demonstrates that the detection was successfully executed and produced an actionable alert rather than merely showing the detection code.\*\***











**## MITRE ATT\&CK Mapping**



**The detection rules are mapped to relevant MITRE ATT\&CK techniques to provide additional context for detected behavior.**



**| Detection                | MITRE ID  | Technique                                     |**

**| ------------------------ | --------- | --------------------------------------------- |**

**| EncodedCommand           | T1027     | Obfuscated/Compressed Files or Information    |**

**| ExecutionPolicy Bypass   | T1059.001 | Command and Scripting Interpreter: PowerShell |**

**| IEX / Invoke-Expression  | T1059.001 | Command and Scripting Interpreter: PowerShell |**

**| DownloadString           | T1105     | Ingress Tool Transfer                         |**

**| FromBase64String         | T1140     | Deobfuscate/Decode Files or Information       |**

**| Hidden PowerShell Window | T1564     | Hide Artifacts                                |**



**MITRE ATT\&CK mapping allows an analyst to associate observed behavior with known adversary techniques and provides useful context during investigation.**



**---**



**## Investigation Workflow**



**When the detector generates an alert, the following investigation process can be followed.**



**### Step 1 — Validate the Alert**



**Review the:**



**\* Indicator**

**\* Severity**

**\* Command line**

**\* Timestamp**

**\* User account**



**Determine whether the detected behavior appears expected or suspicious.**



**### Step 2 — Investigate the Process**



**Review the:**



**\* Process name**

**\* Process ID**

**\* Parent process**



**The parent process can provide important context about how PowerShell was launched.**



**For example, PowerShell launched by an expected administrative process may require a different investigation path from PowerShell launched unexpectedly by another application.**



**### Step 3 — Analyze the Command Line**



**Review the complete command line for:**



**\* Encoded content**

**\* Obfuscation**

**\* Remote URLs**

**\* Download mechanisms**

**\* Dynamic execution**

**\* Execution-policy bypass**

**\* Hidden execution**



**### Step 4 — Decode Obfuscated Content**



**If `-EncodedCommand` or another encoding mechanism is identified, decode the content and inspect the resulting command.**



**The detector automatically attempts Base64 decoding when an `-EncodedCommand` indicator is identified.**



**### Step 5 — Determine User and Context**



**Identify the account associated with the process creation event and determine whether the activity is consistent with the user's expected role and activity.**



**### Step 6 — Document the Finding**



**Record:**



**\* Detection time**

**\* User**

**\* Process**

**\* Parent process**

**\* Command line**

**\* Indicator**

**\* Severity**

**\* MITRE ATT\&CK technique**

**\* Investigation findings**

**\* Final disposition**



**A real SOC environment would then correlate this information with additional telemetry such as endpoint, identity, network, and security-product data.**



**---**



**## Detection Engineering Considerations**



**This project demonstrates several basic detection-engineering principles.**



**### Indicator-Based Detection**



**The detector searches for suspicious characteristics within PowerShell command lines rather than simply alerting whenever PowerShell is executed.**



**This helps reduce the volume of normal PowerShell activity that requires investigation.**



**### Contextual Alerting**



**The alert includes process, user, parent-process, command-line, and timestamp information so that an analyst has useful context immediately available.**



**### Severity**



**Different indicators are assigned different severity levels according to their potential investigative significance.**



**### MITRE ATT\&CK Enrichment**



**Detections are enriched with MITRE ATT\&CK technique information to help analysts understand the type of behavior being observed.**



**### False-Positive Reduction**



**The known lab detector execution is excluded from detection to prevent the detection tool from repeatedly alerting on itself.**



**---**



**## Project Limitations**



**This project is intentionally designed as a \*\*local SOC detection-engineering lab\*\* and should not be considered a production-ready endpoint detection platform.**



**Current limitations include:**



**\* Detection relies primarily on command-line indicators.**

**\* A suspicious indicator does not automatically mean the activity is malicious.**

**\* The project currently analyzes Windows Security Event ID 4688 locally.**

**\* It does not provide centralized log collection.**

**\* It does not currently correlate PowerShell activity with network, identity, or other endpoint telemetry.**

**\* The detection rules may produce false positives in legitimate administrative or automation scenarios.**

**\* The current script processes a rolling 24-hour window rather than continuously monitoring events.**

**\* The project does not currently provide automated containment or remediation.**



**These limitations provide opportunities for future development.**



**---**



**## Future Improvements**



**Potential future enhancements include:**



**1. \*\*Real-time monitoring\*\***



&#x20;  **\* Monitor newly generated process creation events instead of repeatedly scanning a 24-hour window.**



**2. \*\*Additional PowerShell telemetry\*\***



&#x20;  **\* Incorporate PowerShell Script Block Logging and other relevant Windows telemetry.**



**3. \*\*More advanced detection logic\*\***



&#x20;  **\* Detect additional obfuscation techniques and suspicious PowerShell patterns.**



**4. \*\*Network correlation\*\***



&#x20;  **\* Correlate suspicious PowerShell activity with outbound network connections and remote destinations.**



**5. \*\*Centralized SIEM integration\*\***



&#x20;  **\* Forward detection events to a SIEM such as Microsoft Sentinel or another security monitoring platform.**



**6. \*\*Automated investigation\*\***



&#x20;  **\* Enrich alerts with additional endpoint and identity information.**



**7. \*\*Automated response\*\***



&#x20;  **\* Add controlled response actions such as isolating a test endpoint or terminating a malicious process in an appropriate environment.**



**8. \*\*Detection testing framework\*\***



&#x20;  **\* Build repeatable test cases for each detection rule and measure detection coverage.**



**---**



**## Skills Demonstrated**



**This project demonstrates practical experience with:**



**\* Windows Security Event Logs**

**\* Event ID 4688 process creation telemetry**

**\* PowerShell scripting**

**\* PowerShell command-line analysis**

**\* XML event parsing**

**\* Regular-expression based detection**

**\* Security alert generation**

**\* Severity classification**

**\* MITRE ATT\&CK mapping**

**\* Basic false-positive reduction**

**\* Base64 decoding**

**\* SOC alert triage**

**\* Detection engineering**

**\* Security investigation methodology**

**\* Technical documentation**



**---**



**## Project Outcome**



**The project successfully demonstrates a complete basic detection-engineering workflow in a local Windows SOC lab.**



**The detector was tested against controlled suspicious PowerShell activity, including \*\*IEX / Invoke-Expression\*\*, and successfully generated a SOC-style alert with severity, MITRE ATT\&CK mapping, investigation context, and analyst recommendations.**



**The project demonstrates how raw Windows process-creation telemetry can be transformed into a more actionable security detection.**



**---**



**## Key Takeaway**



**The primary objective of this project was not simply to create a PowerShell script, but to understand and demonstrate the process of building a security detection:**



**\*\*Telemetry → Detection Logic → Alert → Context → MITRE Mapping → Investigation\*\***



**This project forms part of a broader hands-on SOC and cloud-security learning lab.**

