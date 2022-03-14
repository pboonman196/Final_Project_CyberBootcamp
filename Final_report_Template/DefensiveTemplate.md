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
