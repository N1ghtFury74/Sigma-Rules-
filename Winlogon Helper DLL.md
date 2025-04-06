Description : 
Winlogon is the Windows component that handles user logon/logoff and the secure attention sequence (Ctrl+Alt+Delete). The system supports **Winlogon helper programs** via specific registry keys. Adversaries abuse these keys to load malicious code at boot or logon for persistence


. Commonly targeted registry paths include:

- **Winlogon\Notify** – Subkeys here define *notification package DLLs* that Winlogon loads on events (logon, logoff, lock, etc.). An attacker can create a new subkey under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\` (or the HKCU equivalent for user-level persistence) with a **`DllName`** value pointing to a malicious DLL. Winlogon will load that DLL on the configured event (e.g. logon) for every user session, executing the malware with SYSTEM privileges.
        
- **Winlogon\Userinit** – Specifies the program(s) run by Winlogon after a user authenticates. By default this is `userinit.exe`, but attackers may append a second executable (e.g. `userinit.exe,<malware>.exe`) in the `Userinit` registry value. This ensures the malware runs at logon alongside the normal userinit.
    
    
- **Winlogon\Shell** – Normally set to `explorer.exe` (the Windows shell). Attackers can change it or add a second program (e.g. `explorer.exe, cmd.exe`) so that their payload starts when the shell starts.
    
Imapct : 


Data Sources for Detection : 
- Sysmon  : Event IDs : 12 (Registry object create/delete) , 13 (Registry value set) , 14 (registry rename) 
- Security Logs Auditing :  Event 4657 (A registry value was modified)

Privlege required : 
-  It typically requires Administrator rights (for HKLM keys affecting all users), though some malware uses the HKCU\Winlogon keys for persistence in the current user context 


Detection : 
- Detection Logic : Any exe will run when the user logon should be added to one of those Winlogon\Userinit and Winlogon\Shell and event notoifcation dll packages should be added to Winlogon\Notify  as Microsoft Douemcnataion mentioned so focusing.
- The Sigma rule 
title: Boot or Logon Autostart Execution: Winlogon Helper DLL
id: 
status: experimental
description: |
  Detects suspicious registry modifications (create/delete, value set, or rename) on the Winlogon persistence keys:
    - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\*
    - HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\*
  
  This rule monitors:
    - Sysmon Event IDs 12, 13, and 14.
    - Windows Security Auditing Event ID 4657 (A registry value was modified).  
      **Note:** Ensure that Event 4657 auditing is enabled.
  
  **False Positives:** Legitimate registry modifications performed by winlogon.exe during system updates or DLL package updates may trigger this rule. Investigate if the DLL location ("dll palace") is outside standard Windows directories.
author: Mohamed Hanii
references:
  - https://attack.mitre.org/techniques/T1547/004/
logsource:
  product: windows
  service: sysmon, security
detection:
  sysmon:
    EventID:
      - 12
      - 13
      - 14
    TargetObject|startswith:
      - "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
      - "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
  security:
    EventID: 4657
    ObjectName|startswith:
      - "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
      - "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
  condition: sysmon or security
falsepositives:
  - Legitimate registry modifications by winlogon.exe (e.g., during system updates or approved DLL package updates)
level: high


Hunting Playbook : 
- Using Velociraptor 

Resources : 
- https://attack.mitre.org/techniques/T1547/004/
- https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/persistence/t1547-boot-or-logon-autostart-execution/winlogon-helper-dll
- https://www.ired.team/offensive-security/persistence/windows-logon-helper
- https://strontic.github.io/xcyclopedia/library/winlogon.exe-E8B1A6B8C6EA5972C123A816DF237AF8.html
- Detection logic change : https://learn.microsoft.com/en-us/windows/win32/secauthn/creating-a-winlogon-notification-package

Draft  : 
TTP Required : 
- As mentioned this component handles what is going on during logon and logoff times so this payload needs to be dropped onto the System23 folder, in this way we can load the legitimate binary and our payload and the same time.
- The registry key that we will focus in this situation is the UserInit. We will need `Administrator` privileges for this technique to work properly.
Detection Logic : 
- Possibiliyt : 
 - Combine registry monitoring (to catch the installation of the persistence) with process/DLL monitoring (to catch the execution of the persisted payload).
    -  Maintain an allow-list of known legit Winlogon\Notify subkeys (Windows defaults like ScCertProp, WgaLogon, etc.)
    - Process Tree of `Winlogon.exe` or `Userinit.exe`
- Image Loaded porblems needed to check that the dll loaded in the winlog.exe and package dll will be difficult to ldetect as dveloper will create it easily , and oither process explorer.exe and userinit.exe
- Detection of DLL loading will focus on winlog.exe as If I fcoused on dll loading in userinit.exe and explorer.exe this will be another technique related to dll loading techniques ir process creation so focusing on this will reduce the flase postsive as - Change plans due to this : https://learn.microsoft.com/en-us/windows/win32/secauthn/creating-a-winlogon-notification-package To use your Winlogon notification package, the DLL must be copied to the %SystemRoot%\system32 folder, and a registry update `must be made for the notification package`. 
