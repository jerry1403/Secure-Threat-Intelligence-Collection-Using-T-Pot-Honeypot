Overview :-

In today’s rapidly evolving threat landscape, organizations must continuously adapt their defenses to emerging cyber risks. This project deployed the T-Pot multi-honeypot platform on Google Cloud Platform (GCP) to proactively collect, analyze, and visualize real-world attack data.
By simulating a range of commonly targeted services, the honeypot attracted attackers from around the globe, enabling the capture of detailed threat intelligence and the identification of malicious actors, their tactics, and their points of origin. The project leveraged advanced 
analytics, secure data transmission, and interactive dashboards to transform raw attack data into actionable insights, supporting both incident response and strategic security planning. 

 

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



Data Collection and Secure Transmission 

Logging and Aggregation: 

T-Pot’s integrated suite of honeypots (e.g., Cowrie, Dionaea, Honeytrap) collected comprehensive logs of all attack attempts, including source IPs, timestamps, payloads, and attacker commands. 
Logs were aggregated in real time and stored locally on the instance for immediate analysis. 

Secure Data Transmission: 

A persistent WireGuard VPN tunnel was established between the GCP honeypot and a centralized on-premises or cloud-based repository. 
This tunnel ensured that all collected data was encrypted in transit, protecting sensitive threat intelligence from interception or tampering. 
Data was periodically synced to the central repository for long-term storage, analysis, and sharing with security teams. 

Advanced Analytics and Visualization 

Elastic Stack Integration: 

T-Pot’s native integration with the Elastic Stack (Elasticsearch, Logstash, Kibana) enabled powerful data indexing, search, and visualization capabilities. 
Custom Kibana dashboards were developed to provide real-time insights into attack trends, top attacker IPs, countries of origin, and most exploited ports. 
Dashboards included interactive charts, maps, and tables, allowing security analysts to drill down into specific events and identify patterns. 

Threat Intelligence Enrichment: 

Collected IP addresses and attack data were enriched using open-source threat intelligence feeds (e.g., VirusTotal) to validate attacker reputation and identify known malicious entities. 
Indicators of Compromise (IOCs) such as IPs, hashes, and domains were extracted and shared with internal security tools to enhance detection and response capabilities. 
Operational Benefits and Insights 

Attack Pattern Analysis: 

Analysis of attack data revealed common tactics such as automated credential stuffing, brute-force attacks, and exploitation of known vulnerabilities. 
The project identified recurring attacker IPs, geographic hotspots, and preferred target services, informing risk assessments and prioritization of security controls. 

Incident Response Support: 

Actionable threat intelligence could have been escalated to Tier 2, enabling faster detection and response to real incidents. 
The project demonstrated the value of honeypots as a force multiplier for security operations, complementing traditional monitoring and detection tools. 

 

Visual Data Highlights :-

I will be attaching a file to this repo as visual. it will contain insights from the T-Pot honeypot deployment, visualized through Kibana dashboards. These highlights provide a snapshot of the most active attackers, their geographic origins, and the services they targeted. 

Conclusion :- 

The Secure Threat Intelligence Collection Using T-Pot Honeypot project exemplifies the power of proactive threat intelligence in modern cybersecurity. By leveraging cloud infrastructure, advanced honeypot technology, and robust analytics, the project delivered deep visibility into attacker behaviors, identified high-risk IPs and countries, and generated actionable IOCs to inform security policies and incident response. The integration of secure data transmission and interactive dashboards ensured that threat intelligence was both comprehensive and actionable, supporting ongoing efforts to defend against evolving cyber threats. This approach not only enhanced the organization’s defensive posture but also provided valuable insights for the broader security community. 

 
