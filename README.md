# LDAPMon

LDAPMon is a POC telemetry collector for the Microsoft-Windows-LDAP-Client ETW Provider. Once started logs will be stored within the EventViewer. This POC comes with a Sentinel parser so that if you want to collect this data within a SIEM you may do so. Used best when ran next to Sysmon. 

## Installation
* Run `LDAPMon.exe`.
* Don't close the LDAPMon window.

## Uninstallation
* Close or stop the LDAPMon process.
* Run `logman stop LDAPMon -ets` from an elevated prompt. 
