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
  # TODO: Insert scan output
```
## Command Explain.

|    Options    |                                            Description                                            |
|:-------------:|:-------------------------------------------------------------------------------------------------:|
| -sV           | Version Detection - Enables version detection                                                     |
| -sT           | TCP Conncect Scan - TCP connect scan is the default TCP scan type when SYN scan is not an option. |
| -A            | Aggressive Scan Options - This option enables additional advanced and aggressive options.         |
| 192.168.1.110 | The IP address of the target machine.                                                             |

This scan identifies the services below as potential points of entry:
- Target 1
  - List of
  - Exposed Services

_TODO: Fill out the list below. Include severity, and CVE numbers, if possible._

The following vulnerabilities were identified on each target:
- Target 1
  - List of
  - Critical
  - Vulnerabilities

_TODO: Include vulnerability scan results to prove the identified vulnerabilities._

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
