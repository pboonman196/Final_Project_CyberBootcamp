# Network Forensic Analysis Report

### Time Thieves 

At least two users on the network have been wasting time on YouTube. Usually, IT wouldn't pay much mind to this behavior, but it seems these people have created their own web server on the corporate network. So far, Security knows the following about these time thieves:

- They have set up an Active Directory network.
- They are constantly watching videos on YouTube.
- Their IP addresses are somewhere in the range 10.6.12.0/24.

You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site?
   - **Frank-n-Ted-DC.frank-n-ted.com**
   - Filter `ip.addr == 10.6.12.0/24`

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/domain_found.png)

2 . What is the IP address of the Domain Controller (DC) of the AD network?
   - **10.6.12.12**
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/ip_domain_controller.png)   

3. What is the name of the malware downloaded to the 10.6.12.203 machine?
   - **june11.dll**
   - Filter: `ip.addr == 10.16.12.203 && http.request.method == GET`

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/malware_detected.png)
Export: file --> Export Objects --> HTTP

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/export_malware_file.png)

4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/). 

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/virus_total.png)

6. What kind of malware is this classified as?
   - **Trojan**

---

## Vulnerable Windows Machine

1. Find the following information about the infected Windows machine:
    - Host name:
      - ROTTERDAM-PC
    - IP address:
      - 172.16.4.205
    - MAC address:
      - 00:59:07:b0:63:a4
    - Filter: `ip.src == 172.16.4.4 && kerberos.CNameString`
    
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/hostname_cname.png)

2. What is the username of the Windows user whose computer is infected?
     - matthijs.devries
     - Filter: `ip.src == 172.16.4.205 && kerberos.CNameString`

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/name_user_infected.png)
    
3. What are the IP addresses used in the actual infection traffic?
     - 172.16.4.205, 166.62.11.64, 185.243.115.84
Based on the conversions: Statistics --> Conversations --> IPv4 --> Packets(High to Low)  

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/ip_traffic_conversation.png)

4. As a bonus, retrieve the desktop background of the Windows host.
     - goto: File --> Export Objects --> HTTP and search for .gif

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/retrive_window_background.png)

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/window_background.png)
      
---

## Illegal Downloads

1. Find the following information about the machine with IP address `10.0.0.201`:
    
    - MAC address
      - 00:16:17:18:66:c8
    - Windows username
      - elmer.blanco  
    - OS version
      - BLANCO-DESKTOP
    - Filter: `ip.src == 10.0.0.201 && kerberos.CNameString`
    
![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/illegal_download_hostname.png)      

2. Which torrent file did the user download? :
     - Betty_Boop_Rythm_on_the_Reservation.avi.torrent
     - Filter: `ip.addr == 10.0.0.201 && (http.request.uri contains ".torrent")`

![](https://github.com/pboonman196/Final_Project_CyberBootcamp/blob/main/Screenshot_network_template/file_name.png)

# End of Summary
