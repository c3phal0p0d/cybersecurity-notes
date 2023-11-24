# Port scanning

## Nmap
__Command:__ ```nmap <scan types> <options> <target/s>```  

### Scan types
- ```-sS```: TCP-SYN (default, requires root privileges)
- ```-sU```: UDP
- ```-sV```: Version - scans services on target & displays their versions
- ```-sT```: Connect() - uses TCP three-way handshake. Most stealthy & accurate for determining the state of a port, and is able to bypass firewalls. However it is slower than other scan types.
- ```-sA```: ACK - harder to filter for firewalls than regular SYN (```-sS```) or Connect  (```-sT```) scans
- ```-sW```: Window
- ```-sM```: Maimon
- ```-sN```: TCP Null
- ```-sF```: FIN
- ```-sX```: Xmas scans
- ```--scanflags <flags>```: Customize TCP scan flags
- ```-sI <zombie host[:probeport]>```: Idle
- ```-sY```: SCTP INIT
- ```-sZ```: COOKIE-ECHO
- ```-sO```: IP protocol
- ```-b <FTP relay host>```: FTP bounce

### Options
- ```-sn```: Disable port scanning
- ```-oA <output filename>```: Save scan output to all formats.
    - ```-oN```: ```.namp``` file format
    - ```-oG```: ```.gnmap``` file format
    - ```-oX```: ```.xml``` file format
- ```-iL <targets list>```: Performs scans against all targets in list
- ```-p <ports>```: Specify ports, either one by one (separated by comma), or as a range
- ```--top-ports=<port>```: Specify which of the top orts (in the top 1000) to scan
- ```-p-```: Scan all ports
- ```-F```: Fast port scan - only top 100 ports
- ```-n```: Deactivate DNS resolution
- ```-v```: Increase verbosity level (```-vv``` to increase even further)
- ```-A```: Aggressive scan
- ```-PE```: Ping scan using 'ICMP Echo requests'
- ```--packet-trace```: Show all packets sent & received
- ```--reason```: Display reason for particular result
- ```--disable-arp-ping```: Disable ARP requests
- ```--iniitial-rtt-timeout <time in ms>```: Set specified time value as initial RTT timeout
    - ```--max-rtt-timeout <time in ms>```: Set specified time value as maximum RTT timeout
    - ```--min-rtt-timeout <time in ms>```: Set specified time value as minimum RTT timeout (default 100ms)
- ```--max-retries <number>```: Set number of retries that will be performed (default 10)
- ```--dns-server <ns>```: Perform DNS resolution using specified nameserver
- ```-e <network interface>```: Specify network interface used for scan
- ```-O```: OS detection
- ```-D RND:<number>```: Set number of random Decoys that will be used to scan target, as a way to disguise the origin of the packet sent.
- ```-S```: Scan target using a different source IP
- ```-g <source port> / --source-port```: Perform scan from specified source port. Useful situations where a firewall only accepts requests from certain ports

### Timing
- ```-T 0 / -T paranoid```
- ```-T 1 / -T sneaky```
- ```-T 2 / -T polite```
- ```-T 3 / -T normal```
- ``` -T 4 / -T aggressive```
- ```-T 5 / -T insane```

### Port states
- ```open```: Indicates that a onnection to the scanned port has been established.  
- ```closed```: Indicates that the packet received back contains an RST flag.  
- ```filtered```: Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or an error code is receieved from the target.  
- ```unfiltered```: This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed.
- ```open|unfiltered```: If a response is not received for a specific port, Nmap will set it to that state. Indicates that a firewall or packet filter may protect the port.
- ```closed|filtered```: This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.

### Scripting
Run default scripts: ```nmap <target> -sC```  
Run specific scripts category: ```nmap <target> --script <category>```  
Rub defined scripts: ```nmap <target> --script <script-name>,<script-name>,...```  

__Script categories:__
- ```auth```: Determination of authentication credentials.
- ```broadcast```: Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans.
- ```brute```: Executes scripts that try to log in to the respective service by brute-forcing with credentials.
- ```default```: Default scripts executed by using the -sC option.
- ```discovery```: Evaluation of accessible services.
- ```dos```: These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.
- ```exploit```: This category of scripts tries to exploit known vulnerabilities for the scanned port.
- ```external```: Scripts that use external services for further processing.
- ```fuzzer```: This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.
- ```intrusive```: Intrusive scripts that could negatively affect the target system.
- ```malware```: Checks if some malware infects the target system.
- ```safe```: Defensive scripts that do not perform intrusive and destructive access.
- ```version```: Extension for service detection.
- ```vuln```: Identification of specific vulnerabilities.