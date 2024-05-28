# Malicious-Network-Traffic-Analysis

## Objective

The objective of the Malicious Network Analysis Lab is to develop a comprehensive understanding of cyber threat investigation by analyzing malicious network traffic. Using a PCAP file generated after a user opened a malicious email and downloaded malware leading to data exfiltration. i gained practical experience in using network analysis tools to investigate and understand the behavior of malware, enhancing my ability to recognize and respond to similar cyber threats.


### Skills Learned

- Advanced understanding of malicious network activities and practical application.
- Proficiency in analyzing and interpreting network traffic.
- Ability to use OSINT tools for threat analysis.
- Enhanced knowledge of network protocols, network security and malware analysis.
- Simulate real-world attacks.

### Tools Used

- Wireshark to examine the sequence of packet transfer via network traffic  from email opening to data exfiltration..
- Virus Total, Abuseipdb,whois.com OSINT tools for Threat Intelligence.
- cyberchef to decode the encoded request/response.
## Steps
Opened the malware PCAP file in Wireshark installed on a virtual machine to prevent infecting the host machine.

[1] Initial Analysis:
The capture properties was reviewed to determine the duration of the capture, noting that it lasted approximately 1 hour. Used the "Conversations" view in Wireshark to identify that host 10.4.10.132 scanned multiple hosts on the network, indicating potential malicious port scanning activity  as scanning should typically only occur during a controlled vulnerability assessment.

![WhatsApp Image 2024-05-28 at 01 37 54_11162777](https://github.com/Ola-11/Maliciou-Network-Traffic-Analysis/assets/90369121/7cb72d2c-578e-4781-ab3a-864e8bdb64c8)

[2] Analyzed Network Traffic:

Identified the IP addresses communicating with external IP addresses and note the amount of packets shared with external IPs compared to other network traffic.

Filter Email Traffic: Since the malware download was initiated by an email, i filter the traffic by SMTP protocol, Follow the HTTPS/TCP stream to analyze the email request/response. 
-Used Cyberchef to decode all encoded content.
-identied the malware exfiltrated all the password saved on the victim computer.

[3] Extract and Analyze Downloaded Files: 

Identified the file that was downloaded from the packet, Generated a File Hash and Check Reputation:
-Used VirusTotal for any known threats and detailed analysis
-Used AbuseIPDB to check the reputation of the external IP address involved in the communication.
-Used Whois domain lookup to gather information about the domain name associated with the external IP address.

## Summary of Incident:
During this investigation,i identified and analyzed a malware infection stemming from a phishing attack. The primary findings and details of the analysis are outlined below.

## Key Findings:

Infection Vector:

-The user accessed the URL proforma-invoices.com via a download link received in an email.
-The user downloaded a file named tkraw_protected99.exe from this URL.

Malware Identification:

-Using VirusTotal and other OSINT tools, the file tkraw_protected99.exe was classified as a trojan named Hawkeye.
-Hawkeye is a known malware with keylogging capabilities, typically delivered via phishing emails.
-The malware communicates with its Command and Control (C&C) server by querying whatismyipaddress.com.

Victim Details:

-Hostname of the infected machine: Beijing-5cd1-pc
-The malware was executed under the authenticated user: sales.del@macwinlogistics.in.

Data Exfiltration:

-The malware exfiltrated files containing password-related contents from the infected machine.

Duration of Compromise:

The total duration of the compromise was 1 hour and 2 minutes.

## Conclusion:
The investigation confirms that the user was targeted by a phishing attack, resulting in the download and execution of the Hawkeye malware. The malware subsequently exfiltrated sensitive password information. This incident underscores the necessity for ongoing network monitoring, enhanced email security protocols, and user training to mitigate the risk of phishing attacks.


