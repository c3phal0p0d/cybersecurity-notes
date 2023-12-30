# File upload attacks

## Absent validation
If validation is absent, any arbitrary file including scripts can be uploaded. To create an appropriate script, first identify the web framework and then write a web shell or reverse shell script in that framework language, then upload it.

## Bypassing client-side validation
### Back-end request modification
Capture the upload request using Burp, and modify the filename to be the appropriate file type, and the content to be the web shell. 

### Disabling front-end validation
Inspect the page's code and either delete or modify the ```accept``` parameter in the ```input``` tag to accept the appropriate file extension. Additionally, delete any other functions that may be responsible for file validation.


## Bypassing blacklist filters
### Fuzzing extensions
Fuzz the upload functionality with a list of potential extensions (such as ```/usr/share/seclists/Discovery/Web-Content/web-extensions.txt``` and see which of them do not return error messages, indicating they are not blacklisted. 

Then upload a file with an extension that has not been blacklisted to execute the code.


## Bypassing whitelist filters
### Double extensions
Modify the filename to contain the whitelisted extension followed by the script extension (e.g. ```shell.jpg.php```).

### Reverse double extensions
Modify the filename to contain the script extension followed by the whitelisted extension (e.g. ```shell.php.jpg```).

### Character injection
Inject several characters before or after the final extension to cause the application to misinterrpet the filename and execute the uploaded file as a script. 

Possible characters that can be injected:
- ```%20```
- ```%0a```
- ```%00```
- ```%0d0a```
- ```/```
- ```.\```
- ```.```
- ```…```
- ```:```

Example of a script to generate all permutations of the file name: 
```
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```


## Bypassing type filters
### Content-Type
Fuzz the Content-Type header with a wordlist such as ```/usr/share/seclists/Miscellaneous/web/content-type.txt```. Then change the Content-Type header in the upload request to be an accepted type.

### MIME-Type
Write some content to the start of the file to trick the application into reading it as that particular file, e.g. adding ```GIF8``` to cause the file to be read as a gif. 


## Limited file upload attacks
Certain file types such as SVG, HTML, XML and some image and document files may allow vulnerabilties to be introduced to the web application by uploading malicious versions of these files.

### XSS
Upload a malicious version of a file to execute code. For instance, an HTML file can contain JavaScript within it which can carry out an attack on whoever visits the uploaded HTML page. 

Another possibility is including an XSS payload in one the metadata paramters of an image in cases where the application displays the image metadata after it is uploaded, triggering the attack. In this case, if the image's MIME-Type is changed to ```text/html``` the attack can be triggered even if the metdata is not directly displayed. This can be accomplished using exiftool:
```
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' <image filoe>
```

SVG images are XML-based and thus can be exploited to include a JavaScript XSS payload within them. Example:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

### XXE
SVG images (as well as other file types that utilize XML such as PDF, Word document and Powerpoint slides) can be exploited to include malicious XML data to leak the source code of the web application as well as other internal documents within the server. 

Example of reading an internal document:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

Example of reading the source code of an application:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

### DOS
A decompression bomb can be created using file types that use data compression such as ZIP archives, by creating an archive containing nested archives within it leading to a large amount of data being decompressed and the server crashing.

Another possible attack is the pixel flood attack using certain image file types that utilize image compression, such as JPG or PNG.

Other attack methods include uploading overly large files in upload forms that do not check for size, or if directory traversal is possible, uploading files to a different directory which can cause the server to crash.


## Other upload attacks
### File name injections
Use a malicious string for the uploaded file name, which may get executed if the uploaded file name is displayed on the page, e.g. ```file$(whoami).jpg```. Similarly, use an XSS payload in the file name such as ```<script>alert(window.origin);</script>``` which would get execuetd on the target's machine, or an SQL query like ```file';select+sleep(5);--.jpg``` which may lead to an SQL injection.

### Upload directory disclosure
Use various methods to look for the uploads directory such as fuzzing, reading source code, exploiting other vulnerabilities, or forcing error messages (for instance by uploading a file with a name that already exists).  

### Windows-specific attacks
Use reserved characters such as ```|```, ```<```, ```>```, ```*```, or ```?``` which if not properly sanitized may be refer to another file and cause errors that disclose the upload directory. Similarly using Windows reserved names for the uploaded file name, such as ```CON```, ```COM1```, ```LPT1``` or ```NUL``` can cause similar errors.
