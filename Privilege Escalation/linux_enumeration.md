# Linux enumeration

Enumeration can be automated using helper scripts such as LinPEAS or LinEnum.

## System information
### OS & Kernel version
Check for the OS and kernel version: ```uname -srm```  
Get more information about the OS version: ```cat /etc/os-release```  
Get more information about the kernel version: ```uname -a``` or ```cat /proc/version```  
Get additional information about the host: ```lscpu```

### Environment variables
Check PATH variable for misconfiguratons: ```echo $PATH```  
List all environment variables: ```env```

### Defenses
Check whether any defenses are in place such as: 
- Exec Shield
- iptables
- AppArmor
- SELinux
- Fail2ban
- Snort
- Uncomplicated Firewall (ufw)

### Shells
Check which login shells exist on the system: ```cat /etc/shells``  

### Users
Get all users on system: ```cat /etc/passwd```  
Get password hashes: ```cat /etc/shadow``` (usually not readable)  
Get existing groups: ```cat /etc/group```  
List members of a particular group: ```getent group <group>```  
Check user's last login: ```lastlog```  
Show users currently logged in: ```w``` or ```who``` or ```finger```

### Networks
Check routing table to see what over networks are available via which interface: ```route``` or ```netstat -rn```  
Check domain resolution if host is configured to use internal DNS: ```cat /etc/resolv.conf```  
Check ARP table to see what other hosts target has beeen communicating with: ```arp -a```  
Show network interfaces: ```ip a```  
Show hosts: ```cat /etc/hosts```


## Processes & services
### Check running processes
Show processes currently running: ```ps au```  
Show current processes started by root: ```ps aux | grep root```

### Sudo
List user's sudo privileges: ```sudo -l```
Check sudo version: ```sudo -V```

### Installed packages & binaries
Find installed packages that may potentially have vulnerabilities: ```apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list```  
Show all binaries: ```ls -l /bin /usr/bin/ /usr/sbin/```  
Check which binaries may be worth investigating later usong GTFOBins: ```for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done```  

### Trace system calls
Track and analyze system calls and signal processing: ```strace```


## Files & directories
### Home directory contents
Check the directory of each of the users in ```/home``` for files such as ```.bash_history```, configuration files and SSH keys.

### Configuration files
Check for the presence of config files for information such as usernames, passwords, and other secrets: ```find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null``` and ```find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null```  

### History files
Show command history of current user: ```history```
Show all history files: ```find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null```

### Temporary files
Show all temporary files: ```ls -l /tmp /var/tmp /dev/shm```  

### Cron jobs
Cron jobs can be found in the ```/etc/cron.daily``` directory. These are tasks that are scheduled to perform maintenance and backup. If there are misconfigrations that can be exploited, cron jobs can be used to escalate privileges when they are run per schedule.

### Proc files
Show proc files, which can reveal information about system processes & hardware: ```find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"```

### File systems & drives
Get information about block devices on the systems (e.g. disks, drives): ```lsblk```  
Check for credentials for mounted drives: ```cat /etc/fstab```  
Show unmounted file systems: ```cat /etc/fstab | grep -v "#" | column -t```
Show mounted file systems: ```df -h```
Get information about printers attached to system: ```lpstat```  
SHow all hidden files: ```find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null```  
Show all hidden directories: ```find / -type d -name ".*" -ls 2>/dev/null```  

If it is possible to mount additional drives or unmounted file systems, sensitive files, passwords or backups may be found that can be leveraged to escalate privileges. Printers may be exploited to print out sensitive information.

### SETUID & SETGID Permissions
Binaries set with these permissions allow users to run the binaries as root, which can be exploietd to gain a root shell

### Writable directories & files
Find writable directories: ```find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null```.

Find writable files: ```find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null```

### Scripts
Find all shell scripts: ```find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"```