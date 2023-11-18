# Brute forcing

## Hydra
__Command:__ ```hydra <options> <target> <module> <module parameters>```

### Options
- ```-C <list>```: combined credentials list
- ```-L <list>```: usernames list
- ```-l <username>```: specific username
- ```-P <list>```: passwords list
- ```-p <password>```: specific password
- ```-s <number>```: specify port
- ```-f```: stop after successful login
- ```-u```: try all users in users list for each password in passwords list
- ```-U```: list usage for particular module

### Modules
- http-get
- http-post-form: ```<Form URL path>:[user parameter]=^USER^&[password parameter]=^PASS^:[F/S]=[failed/success string]```
- ssh
- ftp

### Wordists
__Credentials:__ /usr/share/seclists/Passwords/Default-Credentials  
__Usernames:__ /usr/share/seclists/Usernames/Names/names.txt  
__Passwords:__ /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

### Personalized wordlists
__CUPP__: Tool for generating custom password list based on information about target individual. Run with command ```cupp -i```. Further permutations of the characters in the passwords can be performed using 'mangling'. Output can be modified to remove passwords that do not comply with the password policy using ```sed```.  
__username-anarchy__: Tool for generating custom usernames list based on information about target individual. Command: ```./username-anarchy <first name> <last name>```.