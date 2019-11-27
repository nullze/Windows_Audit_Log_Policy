# Windows_Audit_Log_Policy
Set all audit logs in windows.

AuditPol /set /category:* /success:enable /failure:enable

WevtUtil gl Security

WevtUtil sl Security /ms:524288000

reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v
ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1


# Splunk Searches


# T1087 | Account Discovery
sourcetype="wineventlog:*" ("net user" OR "net group" OR "net localgroup") | table _time, ComputerName, Process_Command_Line

# T1112 | Modify Registry
sourcetype="wineventlog:*" "EventCode=4688" "mim.exe" Process_Command_Line="REG  ADD*" | table _time, ComputerName, Process_Command_Line

# T1082 | Discovery
sourcetype="wineventlog:security" ("whoami" OR "systeminfo") | table _time, ComputerName, Process_Name, Process_Command_Line

# T1064 | Scripting
sourcetype="wineventlog:*" "EventCode=4688" ("*.ps1" OR "*.bat") | table _time, ComputerName, Process_Command_Line

# T1053 | Scheduled Task
sourcetype="wineventlog:*" "EventCode=4688" "schtasks" | table _time, ComputerName, Process_Command_Line

# Geolocation RDP
host="172.16.16.16" dst_port=3389 | iplocation src_ip  allfields=true | geostats globallimit=0 locallimit=0 maxzoomlevel=10 count by City

# Sophos XG Alerts
sourcetype="xg_log" protocol!=ICMP log_subtype=Alert  | table date, time, threatname, sourceip, destinationip, url

# RDP Successful
sourcetype="*" EventCode=4624 Logon_Type=10 NOT "172.16.16.*" | top Source_Network_Address

# PiHole Top 10 DNS Queries
sourcetype="pihole" Hostname="*" AND Hostname !="result" AND IP!="0.0.0.0" AND Hostname!=*google* AND Hostname!="pool.ntp.org" AND Hostname!="*.cloudfront.net*" | top 10 Hostname

# PiHole Top 10 Blocked Hostnames
sourcetype="pihole" "0.0.0.0" | top Hostname

# Sophos XG Top 10 Attacks
sourcetype="xg_log" "priority=Warning" AND signature_msg!="TCP Timestamp is missing" AND signature_msg!="Data sent on stream after TCP Reset received" AND signature_msg!="TCP Timestamp is outside of PAWS window" AND signature_msg!="Data sent on stream not accepting data" AND signature_msg!="Data sent on stream after TCP Reset sent" | top signature_msg

# Sophos XG GUI Authentication
host="172.16.16.16" AND "log_component="GUI""

# Sophos XG DDNS Update
host="172.16.16.16" "log_component="DDNS""

# Splunk Access Attempts
index=_audit sourcetype=audittrail user=* action=log* | top src

# Windows Endpoint BAT & PS1
sourcetype="wineventlog:*" "EventCode=4688" ("*.ps1" OR "*.bat") | table _time, ComputerName, Process_Command_Line

# Windows RDP Destination Addresses
EventCode=5156 Source_Port=3389 | top 100 Destination_Address

# Windows New Services Started
sourcetype="wineventlog*"  EventCode="7045" | table ComputerName, Service_File_Name

# Kerberosting (In Progress)
sourcetype="wineventlog:*" EventCode="4776"

# Pass The Hash (In Progress)
sourcetype="wineventlog:security" "ntlmssp" | table ComputerName, Source_Network_Address
