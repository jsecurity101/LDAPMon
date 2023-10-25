# LDAPMon

LDAPMon is a POC telemetry collector for the Microsoft-Windows-LDAP-Client ETW Provider. Once started logs will be stored within the EventViewer. This POC comes with a Sentinel parser so that if you want to collect this data within a SIEM you may do so. Used best when ran next to Sysmon. 

## Installation
* Open a cmd or powershell prompt as Administrator. 
* Run `LDAPMon.exe`.
* Don't close the LDAPMon window.
If everything was successful you will see this: 
```
.\LDAPMonitor.exe
[*] Uninstalling Manifest....
[*] Manifest Uninstalled....
[*] LDAPMon.dll Copied to C:\Windows\LDAPMon.dll
[*] Installing Manifest....
[*] Manifest Installed....
[*] Starting LDAPMon...
[+] LDAP Trace Enabled

```

## Uninstallation
* Close or stop the LDAPMon process.
* Run `logman stop LDAPMon -ets` from an elevated prompt. 
