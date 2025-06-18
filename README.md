![Tpot-wireguard-wazuh](https://github.com/user-attachments/assets/7f5498d7-3ed5-43d1-8ad3-2acd839fdd03)


Overview :-

In today’s rapidly evolving threat landscape, organizations must continuously adapt their defenses to emerging cyber risks. This project deployed the T-Pot multi-honeypot platform on Google Cloud Platform (GCP) to proactively collect, analyze, and visualize real-world attack data.
By simulating a range of commonly targeted services, the honeypot attracted attackers from around the globe, enabling the capture of detailed threat intelligence and the identification of malicious actors, their tactics, and their points of origin. The project leveraged advanced 
analytics, secure data transmission, and interactive dashboards to transform raw attack data into actionable insights, supporting both incident response and strategic security planning. 

![Secure Threat Intelligence Collection Using T-Pot Honeypot (1)](https://github.com/user-attachments/assets/351de82a-5ed5-4c60-9e91-fb0b6bbf0614)



Technical Summary :-

Platform Deployment and Architecture

Cloud Infrastructure: 

The T-Pot honeypot was deployed on a Google Cloud Compute Engine instance, selected for its robust security features, scalability, and global network presence. 
The instance was configured with sufficient CPU, memory, and SSD storage to handle high volumes of malicious traffic and data processing. 
A static external IP address was assigned to maximize exposure and attract a diverse range of attackers. 

Service Simulation: 

T-Pot was configured to simulate a wide array of vulnerable services, including SSH (port 22), Telnet (port 23), HTTP/HTTPS (ports 80/443), UDP (port 8888), TCP (port 4719), and additional services such as FTP (port 21) and TCP (port 5555). 
Each simulated service was designed to mimic real-world vulnerabilities, enticing attackers to interact and reveal their methods. 

Security and Isolation: 

The honeypot was deployed in a dedicated virtual private cloud (VPC) with strict firewall rules to prevent any accidental exposure of internal resources. 
All inbound traffic was logged, while outbound connections were tightly controlled to prevent the honeypot from being used as a launchpad for further attacks. 

![firewallrules](https://github.com/user-attachments/assets/9d66d792-7368-4a20-acdf-d48eda8399c0)




Data Collection and Secure Transmission 

Logging and Aggregation: 

T-Pot’s integrated suite of honeypots (e.g., Cowrie, Dionaea, Honeytrap) collected comprehensive logs of all attack attempts, including source IPs, timestamps, payloads, and attacker commands. 
Logs were aggregated in real time and stored locally on the instance for immediate analysis. 

Secure Data Transmission: 

A persistent WireGuard VPN tunnel was established between the GCP honeypot and a centralized on-premises or cloud-based repository. 
This tunnel ensured that all collected data was encrypted in transit, protecting sensitive threat intelligence from interception or tampering. 
Data was periodically synced to the central repository for long-term storage, analysis, and sharing with security teams. 

![wireguardtunnel](https://github.com/user-attachments/assets/0e57391e-23d9-46bd-9300-5bf8c2202b58)

Advanced Analytics and Visualization 

Elastic Stack Integration: 

T-Pot’s native integration with the Elastic Stack (Elasticsearch, Logstash, Kibana) enabled powerful data indexing, search, and visualization capabilities. 
Custom Kibana dashboards were developed to provide real-time insights into attack trends, top attacker IPs, countries of origin, and most exploited ports. 
Dashboards included interactive charts, maps, and tables, allowing security analysts to drill down into specific events and identify patterns. 

Threat Intelligence Enrichment: 

Collected IP addresses and attack data were enriched using open-source threat intelligence feeds (e.g., VirusTotal) to validate attacker reputation and identify known malicious entities. 
Indicators of Compromise (IOCs) such as IPs, hashes, and domains were extracted and shared with internal security tools to enhance detection and response capabilities. 

![redishoneypot10country](https://github.com/user-attachments/assets/eb459c0a-f29e-4930-87c3-5bb4154391b1)
![honeytrap10IP](https://github.com/user-attachments/assets/3aaa9d4b-a665-4b38-9bac-a20129f2ceae)
![suricataCVE10](https://github.com/user-attachments/assets/abf783a4-6ebd-488b-957a-838514f99bc1)


Operational Benefits and Insights 

Attack Pattern Analysis: 

Analysis of attack data revealed common tactics such as automated credential stuffing, brute-force attacks, and exploitation of known vulnerabilities. 
The project identified recurring attacker IPs, geographic hotspots, and preferred target services, informing risk assessments and prioritization of security controls. 

Incident Response Support: 

Actionable threat intelligence could have been escalated to Tier 2, enabling faster detection and response to real incidents. 
The project demonstrated the value of honeypots as a force multiplier for security operations, complementing traditional monitoring and detection tools. 

![toptechniques](https://github.com/user-attachments/assets/5a5ca44d-12fa-47b0-a70f-c0b5109a32d9)
![topctactics](https://github.com/user-attachments/assets/42897796-aad7-42cc-8796-2993a4ba1914)

 

Visual Data Highlights :-

Below are representative insights from the T-Pot honeypot deployment, visualized through Kibana dashboards. These highlights provide a snapshot of the most active attackers, their geographic origins, and the services they targeted. 

![dionaea10country](https://github.com/user-attachments/assets/a73acd03-80b2-44c1-bfac-403af0aa30b5)
![redishoneypot10country](https://github.com/user-attachments/assets/f3c2bcfd-8d85-4d6f-b83b-33c884a4cfd0)
![dionaea10port](https://github.com/user-attachments/assets/64440506-bef5-4e71-bea5-bfa9f8bd271f)
![dionaea10IP](https://github.com/user-attachments/assets/8a54d0fe-2d79-4818-8e89-f27673e854d1)
Binary/Payload planting exploiting SMB
source: Dionaea Logs

![honeytrap10country](https://github.com/user-attachments/assets/7b47732e-3f78-4c89-a0a6-3225576ae3b9)
![honeytrap10port](https://github.com/user-attachments/assets/8e8bdb0c-d24e-49fc-a436-69d0a36d2b0c)
![honeytrap10IP](https://github.com/user-attachments/assets/93f60ff3-11fb-4c37-93e1-c943a1b9d8ba)
Authentication attempts at non-standard service ports
source: Honeytrap Logs

![cowrie10country](https://github.com/user-attachments/assets/d86bcc15-eb5c-4a08-a681-afd51d5df6c0)
![Overall10Ports](https://github.com/user-attachments/assets/637d3bbb-b6c2-4242-82e1-20cd93ba7351)
![cowrie10IP](https://github.com/user-attachments/assets/88054a34-42b4-437c-ad40-6d93ad10e36b)
Unauthorized SSH attempts
source: Cowrie Logs

![p0f10OS](https://github.com/user-attachments/assets/9e0bd778-9760-4d92-80bf-874aaf8457d8)
OS fingerprinting TCP/IP packets
source: P0f 

![mostsuricataAlertDescription](https://github.com/user-attachments/assets/4262df14-70f9-4e9f-ba32-34b20acbd800)
Exploitation attempts
*Binaries caught on Dionaea, YARA found wannacry strings*
Source: Suricata NIDS




Conclusion :- 

The Secure Threat Intelligence Collection Using T-Pot Honeypot project exemplifies the power of proactive threat intelligence in modern cybersecurity. By leveraging cloud infrastructure, advanced honeypot technology, and robust analytics, the project delivered deep visibility into attacker behaviors, identified high-risk IPs and countries, and generated actionable IOCs to inform security policies and incident response. The integration of secure data transmission and interactive dashboards ensured that threat intelligence was both comprehensive and actionable, supporting ongoing efforts to defend against evolving cyber threats. This approach not only enhanced the organization’s defensive posture but also provided valuable insights for the broader security community. 






 
