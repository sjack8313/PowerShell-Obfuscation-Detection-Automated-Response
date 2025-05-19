
# PowerShell Obfuscation Detection & Automated Response

This detection engineering project identifies malicious PowerShell behavior in Windows environments — specifically the use of obfuscated or encoded commands and suspicious execution methods such as `iex` and `DownloadString`. These are often used by attackers to download and run payloads in memory without touching disk.

---

##  Objective

Detect and respond to PowerShell abuse using:
-  Splunk SPL to identify suspicious command patterns
- 🛠 Python-based SOAR automation to simulate response actions (e.g., block source IP)
- Screenshots from a test environment to visualize attacker activity

---

##  MITRE ATT&CK Mapping

| Tactic          | Technique                     | ID           |
|----------------|-------------------------------|--------------|
| Execution       | PowerShell                    | T1059.001    |
| Defense Evasion | Obfuscated Files or Information | T1027        |
| Command and Control | Ingress Tool Transfer     | T1105        |

---

## Detection Logic

We focus on:
- Windows Event ID `4104` (PowerShell Script Block Logging)
- Event ID `4688` (Process Creation)
- Key indicators: `Invoke-Mimikatz`, `FromBase64String`, `iex`, and encoded commands

###  SPL Query

```spl
index=windows EventCode=4104 OR EventCode=4688
| eval PowershellCommand=coalesce(ScriptBlockText, CommandLine)
| where like(PowershellCommand, "%Invoke-Mimikatz%") 
    OR like(PowershellCommand, "%FromBase64String%") 
    OR like(PowershellCommand, "%iex%")
| stats count by _time, host, user, PowershellCommand
