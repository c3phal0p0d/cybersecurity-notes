# Hacking WordPress

## Structure
After installation, all WordPress related files will be located in the  ```/var/www/html``` directory.

__Important files & directories:__
- ```index.php```: homepage of WordPress.
- ```license.txt```: contains useful information such as the version WordPress installed.
- ```wp-activate.php```: used for the email activation process when setting up a new WordPress site.
- ```wp-admin/```: folder containing the login page for administrator access and the backend dashboard. Once a user has logged in, they can make changes to the site based on their assigned permissions. The login page can be located at one of the following paths:
    - ```/wp-admin/login.php```
    - ```/wp-admin/wp-login.php```
    - ```/login.php```
    - ```/wp-login.php```
    
    This file can also be renamed to make it more challenging to find the login page.
- ```wp-config.php```: file containing information required by WordPress to connect to the database, such as the database name, database host, username and password, authentication keys and salts, and the database table prefix.
- ```xmlrpc.php```: file representing a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism. This type of communication has been replaced by the WordPress REST API.
- ```wp-content/```: main directory where plugins and themes are stored. The subdirectory ```uploads/``` is usually where any files uploaded to the platform are stored.
- ```wp-includes/```: contains everything except for the administrative components and the themes that belong to the website. This is the directory where core files are stored, such as certificates, fonts, JavaScript files, and widgets.

## Enumeration
### Version
Find the ```generator``` tag in the source code, or use the following command: ```curl -s -X GET http://<target> | grep '<meta name="generator"'```. Also useful to look at links to CSS and JS documents to gain information about the version.

### Plugins & Themes
Plugins: ```curl -s -X GET http://<target> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*'```

Themes: ```curl -s -X GET http://<target> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes'```

To actively enumerate plugins & themes, send a GET request for a particular plugin/theme. If it does not return a 404 error, then it exists on the server. Example:  ```curl -I -X GET http://<target>/wp-content/plugins/<plugin>```

### Users
Checking whether a particular user exists: ```curl -s -I -X GET http://<target>/?author=<id>```. If the response is not 404, then a user with that ID exists.

Getting a list of all users: ```curl http://<target>/wp-json/wp/v2/users | jq```

Checking if credentials are correct: ```curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://<target>/xmlrpc.php```

## WPScan
Automated tool for scanning & enumerating WordPress sites.

__Command:__ ```wpscan --url http://<target> <options>```

__Options:__
- ```--enumerate```: Enumerate various components of application
- ```--api-token <token>```: Specify WPVulnDB API token, which will be used to pull in vulnerability information from external sources
- ```--password-attack <type>```: Perform brute force login attack
- ```-U <list>```: List of usernames
- ```-P <list>```: List of passwords
- ```-v```: Verbose mode
- ```-t <number>```: Specify number of threads
