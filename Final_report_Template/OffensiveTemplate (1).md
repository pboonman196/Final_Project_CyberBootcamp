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

The target1 has been discovered to be vulnerable to exploit in a variety of ways, and our research team, as a red team, has successfully penetrated the target1, as illustrated in the step below.

- Target 1
  - Command used to enumerate user and check all vulnerable theme, outdated plugin on the wordpress site:
  
  ```bash
  $ wpscan --url http://192.168.1.110/wordpress --rua --enumerate u
  ```
  - After running this command, we are can see that this wordpress site username is exposed to the public.
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/Screenshot%20(234).png)  

  - Since the target1 is vulnerable to ssh-bruteforcing, we can use hydra to run the password list against the username to login, in this case we will try with michael

```bash
  $ hydra -l michael -P /usr/share/wordlists/rockyou.txt 192.168.1.110 -t 4 ssh
```

## Command Explain

| Options | Description                                                                |
|---------|----------------------------------------------------------------------------|
| hydra   | A very fast network logon cracker which support many different services    |
| -l      | Login - or -L FILE login with LOGIN name, or load several logins from FILE |
| -p      | PASS - or -P FILE try password PASS, or load several passwords from FILE   |
| -t      | TASKS - run TASKS number of connects in parallel (default: 16)             |

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/hydra_bruteforce_ssh.png)
   
  - After we optained the credential, we can begin loging into the target using SSH.
```bash
  $ ssh michael@192.168.1.110
```
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/SSH_login.png)

  - `flag1.txt`: flag1{9bbcb33e11b80be759c4e844862482} `flag1.txt` hash value_
    - **Exploit Used**
    - flag1 can easily discover using gobuster to discover the directories of the target1 sites. We used gobuster to done this job.
```bash
  $ gobuster dir -e -u http://192.168.1.110/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/gobuster_command.png)
## Command Explain

| Options | Description                                   |
|---------|-----------------------------------------------|
| dir     | Used for directory/file bruteforcing.         |
| -e      | Expanded mode, print full URLs.               |
| -u      | (-username [string]) Username for Basic Auth. |
| -w      | (-wordlist [wordlist]) Path to wordlist.      |

   - we are now able go by the directory uncovered by gobuster and we eventually found the flag1 by just inspecting the service.html page.
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/discovered_flag1.png)
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
  - `flag2.txt`: _TODO: Insert `flag2.txt` hash value_
    - **Exploit Used**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
