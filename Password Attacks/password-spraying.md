# Password spraying

## CrackMapExec
__Command:__ ```crackmapexec <protocol> <target> <options>```

### Protocols
- ```ftp```
- ```ssh```
- ```mssql```
- ```winrm```
- ```rdp```
- ```smb```
- ```ldap```

### Options
- ```-u <list>```: specific username of list of usernames
- ```-p <password>```: specific password or list of passwords
- ```--continue-on-success```: continue spraying even after a valid password is found
- ```--local-auth```: use this option when targeting a non-domain joined computer