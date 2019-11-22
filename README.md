# Windows_Audit_Log_Policy
Set all audit logs in windows.

AuditPol /set /category:* /success:enable /failure:enable

WevtUtil gl Security

WevtUtil sl Security /ms:524288000

reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v
ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
