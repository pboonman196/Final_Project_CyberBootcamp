# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services
Use nmap to enumerate the target and find the exposed service.

Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -sV -sT -A 192.168.1.110
  
```
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/nmap_scan_result.png)

## Command Explain.

|    Options    |                                            Description                                            |
|:-------------:|:-------------------------------------------------------------------------------------------------:|
| -sV           | Version Detection - Enables version detection                                                     |
| -sT           | TCP Conncect Scan - TCP connect scan is the default TCP scan type when SYN scan is not an option. |
| -A            | Aggressive Scan Options - This option enables additional advanced and aggressive options.         |
| 192.168.1.110 | The IP address of the target machine.                                                             |

This scan identifies the services below as potential points of entry:
- Target 1
  - 22/TCP - SSH
  - 80/TCP - HTTP
  - 139/TCP - SMB
  - 445/TCP - SMB
  - 111/TCP - RPCBind

The following vulnerabilities were identified on target1 machine:

| Vulnerabilities | Critical rating | Port    | Version/Website Page             | Description                                                                                                                                                    |
|-----------------|-----------------|---------|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2015-5600   | 8.5             | 22/SSH  | OpenSSH 6.7p1 Debian             | Remote attacker can conduct brute-force  attacks or cause a denial of service                                                                                  |
| CVE-2021-44790  | 7.5             | 80/HTTP | Apache 2.4.10 Debian             | A carefully crafted body can cause a buffer overflow in the  mod_lua multipart parser.                                                                         |
| Service regsvc  | 5.0             | 139/SMB | netbios-ssn Samba smbd 3.x - 4.x | Service regsvc in Microsoft Windows 2000 systems is vulnerable to  denial of service caused by null deference.                                                 |
| DOM-based XSS   | 6.0             | 80/HTTP | http://192.168.1.110/contact.php | XSS discoverd by running burpsuite scan shown possibility of XSS,  an attacker can tamper with the HTML response body an send it as client-side request(CSRF). |

### Exploitation
_TODO: Fill out the details below. Include screenshots where possible._

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: _TODO: Insert `flag1.txt` hash value_
    - **Exploit Used**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
  - `flag2.txt`: _TODO: Insert `flag2.txt` hash value_
    - **Exploit Used**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
