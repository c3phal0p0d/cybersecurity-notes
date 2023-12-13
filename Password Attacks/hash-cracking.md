# Hash cracking

## Identifying hashes
### hashid
Python tool for identifying hashes.
Install with command ```pip install hashid```.

Usage: ```hashid <hash | hash file>```. Use option ```-m``` to also provide the corresponding hashcat hash type.

## Hashcat
__Command:__ ```hashcat <options> <hash|hash file> <wordlist>```

Previously cracked passwords are stored in the ```~/hashcat.potfile``` file.

### Options
- ```-a```: Attack mode
    - ```0```: Straight (Default)
    - ```1```: Combination
    - ```3```: Mask attack
    - ```6```: Hybrid: wordlist & mask
    - ```7```: Hybrid: mask & wordlist
- ```-m```: Hash type
- ```-b```: Perform benchmark test for a particular hash type
- ```-O```:  Enable optimized kernels (limits password length)
- ```-w```: Enable specific workload profile

### Attack Types
__Straight__   
```hashcat -a 0 -m <hash type> <hash file> <wordlist>```

__Combination__   
```hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>```

__Mask attack__  
```hashcat -a 3 -m <hash type> <hash> <mask>``` where the mask consists of sybols that should be in the password along with placeholders.

Possibilities for placeholders:
- ```?l```: lower-case ASCII letters (a-z)
- ```?u```: upper-case ASCII letters (A-Z)
- ```?d```: digits (0-9)
- ```?h```: 0123456789abcdef
- ```?H```: 0123456789ABCDEF
- ```?s```: special characters («space»!"#$%&'()*+,-./:;<=>?@[]^_`{
- ```?a```: ?l?u?d?s
- ```?b```: 0x00 - 0xff

__Hybrid: Wordlist & mask__  
Appends the string generated from the mask to the end of each word in the wordlist.
```hashcat -a 6 -m <hash type> <hash> <wordlist> <mask>```

__Hybrid: Mask & wordlist__  
Prepends the string genereated from the mask to the end of each word in the wordlist.

```hashcat -a 7 -m <hash type> <hash> <mask> <wordlist>```

### Rule-based attack

### Hashcat-utils
A [repository](https://github.com/hashcat/hashcat-utils) containing many utilities that can be downloaded to use for more advanced password cracking.

## John the Ripper

## Custom wordlists
### Crunch

### CUPP

### KWProcessor

### PrinceProcessor

### CeWL
Scrapes website and creates list of the words present. Command: ```cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>```