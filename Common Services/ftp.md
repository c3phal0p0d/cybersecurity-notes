# FTP
The File Transfer Protocol (FTP) is an application-layer protocol which is used for sharing files. It utilises two ports, port 21 for sending commands and port 20 for sending the actual data. Credentials are usually needed to use FTP, but sometimes anonymous access is enabled, in which case use the name ```anonymous``` to login. The protocol is clear-text so can be detected if network conditions are right. TFTP is a simple version of FTP without user authentication and other features.

## Basic commands
- ```ftp <IP address>```: Connect to FTP server
- ```status```: Get information on the server's settings. Useful for checking if any settings have been misconfigured
- ```ls```: List files
    - ```-R```: Option to recursively list files
- ```get <filename>```: Download file to local machine
- ```put <filename>```: Upload file from local machine to server
- ```exit```: Exit

## Attacks
### Anonymous authentication
Check if anonymous authentication is enabled by specifying the Nmap flag ```-sC ``` which includes the ftp-anon script.

### Brute force
Brute force login with a tool such as Hydra or Medusa.

### FTP bounce
Perform this attack with Nmap by specifying the option ```-b anonymous:password@<target IP>```