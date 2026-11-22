# AA23-319A 标注审核

新提议按行为 ID 和映射 ID 在 review_decisions.json 中分别填写决策。

可用操作为 accept、edit、reject、insufficient_evidence。

## AA23-319A-P001

PDF 第 4 页 · observed · high · draft

**行为** Authenticated to internal VPN access points using compromised valid credentials → victim network VPN

**上下文说明** The advisory describes this as observed Rhysida activity, particularly where MFA was not enabled by default.

**引文**

    Rhysida actors have been observed leveraging external-facing remote services to initially access and 
    persist within a network. Remote services, such as virtual private networks (VPNs), allow users to connect 
    to internal enterprise network resources from external locations. Rhysida actors have commonly been 
    observed authenticating to internal VPN access points with compromised valid credentials, 
    notably due to organizations lacking MFA enabled by default.

**同页前后文**

    ditionally, open source reporting[2] has confirmed observed 
    instances of Rhysida actors operating in a ransomware-as-a-service (RaaS) capacity, where ransomware 
    tools and infrastructure are leased out in a profit-sharing model. Any ransoms paid are then split between 
    the group and the associates.  
    For additional information on Vice Society actors and associated activity, see the joint advisory 
    #StopRansomware: Vice Society. 
    Initial Access 
    Rhysida actors have been observed leveraging external-facing remote services to initially access and 
    persist within a network. Remote services, such as virtual private networks (VPNs), allow users to connect 
    to internal enterprise network resources from external locations. Rhysida actors have commonly been 
    observed authenticating to internal VPN access points with compromised valid credentials, 
    notably due to organizations lacking MFA enabled by default. 
    Update April 30, 2025 
    Rhysida actors have also used Gootloader malware at times for initial access. 
    Update End 
    Living off the Land 
    Analysis identified Rhysida actors using living off the land techniques, such as creating Remote Desktop 
    Protocol (RDP) connections for lateral movement, establishing VPN access, and utilizing 
    PowerShell. Living off the land techniques include using native (built into the operating 
    system) network administrat

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM001 · T1133 External Remote Services · high · draft
  The report explicitly describes authentication to internal VPN access points, matching use of external remote services.
- AA23-319A-PM002 · T1078 Valid Accounts · high · draft
  Compromised valid credentials were used to authenticate, directly matching Valid Accounts.

**候选** T1133, T1078, T1187, T1650, T1056.003, T1499, T1110, T1213, T1210, T1199, T1078.004, T1557.001, T1589.001, T1550.001, T1649, T1110.001, T1114.003, T1078.001, T1589.002, T1136.003, T1556.006, T1098.001, T1556, T1598.003
**映射复查** The more specific account sub-techniques in the expanded set are not supported: the report does not identify default or cloud accounts. It also does not describe brute force or credential theft.

## AA23-319A-P002

PDF 第 4 页 · observed · high · draft

**行为** Created RDP connections for lateral movement and established VPN access → victim network

**上下文说明** The advisory describes these as living-off-the-land techniques used by Rhysida actors.

**引文**

    Analysis identified Rhysida actors using living off the land techniques, such as creating Remote Desktop 
    Protocol (RDP) connections for lateral movement, establishing VPN access, and utilizing 
    PowerShell. Living off the land techniques include using native (built into the operating 
    system) network administration tools to perform operations. This allows the actors to evade detection by 
    blending in with normal Windows systems and network activities.

**同页前后文**

     as virtual private networks (VPNs), allow users to connect 
    to internal enterprise network resources from external locations. Rhysida actors have commonly been 
    observed authenticating to internal VPN access points with compromised valid credentials, 
    notably due to organizations lacking MFA enabled by default. 
    Update April 30, 2025 
    Rhysida actors have also used Gootloader malware at times for initial access. 
    Update End 
    Living off the Land 
    Analysis identified Rhysida actors using living off the land techniques, such as creating Remote Desktop 
    Protocol (RDP) connections for lateral movement, establishing VPN access, and utilizing 
    PowerShell. Living off the land techniques include using native (built into the operating 
    system) network administration tools to perform operations. This allows the actors to evade detection by 
    blending in with normal Windows systems and network activities.  
    Ipconfig, whoami, nltest, and several net commands have been used to 
    enumerate victim environments and gather information about domains. In one instance of using 
    compromised credentials, actors leveraged net commands within PowerShell to identify logged-in users 
    and perform reconnaissance on network accounts within the victim environment. Note: The following 
    commands were not performed in the exact order listed. 
     net user [username] /dom

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM003 · T1021.001 Remote Desktop Protocol · high · draft
  The report explicitly states that the actors created RDP connections for lateral movement, matching Remote Desktop Protocol.
- AA23-319A-PM004 · T1133 External Remote Services · high · draft
  The report separately describes establishing VPN access, matching External Remote Services.

**候选** T1563.002, T1021, T1021.001, T1072, T1219, T1187, T1570, T1505.005, T1070.007, T1098.007, T1105, T1003.001, T1563, T1133, T1574.001, T1572, T1059.013, T1049, T1210, T1665, T1021.008, T1543.003, T1136.003, T1040
**映射复查** The expanded candidates do not support session hijacking, tool transfer, or persistence through terminal-services components. VPN and RDP use are directly stated.

## AA23-319A-P003

PDF 第 4 页 · observed · high · draft

**行为** Used domain commands to identify logged-in users and perform account reconnaissance → victim environment domain accounts

**上下文说明** In one instance, compromised credentials were used; the commands ran within PowerShell.

**引文**

    Ipconfig, whoami, nltest, and several net commands have been used to 
    enumerate victim environments and gather information about domains. In one instance of using 
    compromised credentials, actors leveraged net commands within PowerShell to identify logged-in users 
    and perform reconnaissance on network accounts within the victim environment. Note: The following

**同页前后文**

     identified Rhysida actors using living off the land techniques, such as creating Remote Desktop 
    Protocol (RDP) connections for lateral movement, establishing VPN access, and utilizing 
    PowerShell. Living off the land techniques include using native (built into the operating 
    system) network administration tools to perform operations. This allows the actors to evade detection by 
    blending in with normal Windows systems and network activities.  
    Ipconfig, whoami, nltest, and several net commands have been used to 
    enumerate victim environments and gather information about domains. In one instance of using 
    compromised credentials, actors leveraged net commands within PowerShell to identify logged-in users 
    and perform reconnaissance on network accounts within the victim environment. Note: The following 
    commands were not performed in the exact order listed. 
     net user [username] /domain 
     net group “domain computers” /domain 
     net group “domain admins” /domain  
     net localgroup administrators  
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM005 · T1087.002 Domain Account · high · draft
  The report describes reconnaissance on network/domain accounts, directly matching Domain Account discovery.
- AA23-319A-PM006 · T1033 System Owner/User Discovery · high · draft
  The report explicitly states that actors identified logged-in users, matching System Owner/User Discovery.

**候选** T1087, T1033, T1528, T1021, T1049, T1482, T1069.003, T1598.003, T1580, T1590.001, T1484, T1550.001, T1187, T1548.005, T1201, T1591.002, T1654, T1087.002, T1484.002, T1586.002, T1564.006, T1681, T1098.001, T1597.002
**映射复查** The expanded set supports the more specific domain-account discovery mapping. The report does not say the actors discovered or modified domain trust relationships.

## AA23-319A-P004

PDF 第 5 页 · observed · high · draft

**行为** Launched PowerShell ISE before executing a malicious script → compromised Windows system

**上下文说明** The advisory identifies the script as 1.ps1 from a temporary AppData folder.

**引文**

    Rhysida actors have been observed launching Windows PowerShell Integrated 
    Scripting Environment (ISE) prior to executing a malicious script (1.ps1 from a folder 
    in %AppData%\Local\Temp%). PowerShell ISE provides a graphical interface for 
    editing and testing PowerShell scripts.

**同页前后文**

    plication that allows users to manage and interact with their cloud storage. 
    Table 1: Tools Leveraged by Rhysida Actors 
    Disclaimer: Organizations are encouraged to investigate and vet use of these tools prior to performing 
    remediation actions. 
    Name Description 
    cmd.exe  The native command line prompt utility. 
    PowerShell.exe A native command line tool used to start a Windows PowerShell session in a Command Prompt window. 
    powershell_ise.exe 
    Rhysida actors have been observed launching Windows PowerShell Integrated 
    Scripting Environment (ISE) prior to executing a malicious script (1.ps1 from a folder 
    in %AppData%\Local\Temp%). PowerShell ISE provides a graphical interface for 
    editing and testing PowerShell scripts. 
    PsExec.exe A tool included in the PsTools suite used to execute processes remotely. Rhysida actors heavily leveraged this tool for lateral movement and remote execution. 
    mstsc.exe A native tool that establishes an RDP connection to a host. 
    PuTTY.exe 
    Rhysida actors have been observed creating Secure Shell (SSH) PuTTy connections for 
    lateral movement. In one example, analysis of PowerShell console host history for a 
    compromised user account 

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM007 · T1059.001 PowerShell · high · draft
  The behavior explicitly describes launching PowerShell ISE before executing a malicious script, supporting PowerShell execution.

**候选** T1546.013, T1059.007, T1547.001, T1564.006, T1574.011, T1059.001, T1546.008, T1546.012, T1220, T1218.011, T1546.004, T1574.007, T1608.004, T1689, T1548.003, T1497.001, T1546.015, T1546.016, T1059, T1574.005, T1547.015, T1553.006, T1195.001, T1055.011
**映射复查** No expanded candidate for PowerShell profiles or other persistence mechanisms is supported; the behavior describes script execution.

## AA23-319A-P005

PDF 第 5 页 · observed · high · draft

**行为** Used PsExec for lateral movement and remote execution → remote victim systems

**上下文说明** The advisory states Rhysida actors heavily leveraged this tool for these actions.

**引文**

    PsExec.exe A tool included in the PsTools suite used to execute processes remotely. Rhysida actors heavily leveraged this tool for lateral movement and remote execution.

**同页前后文**

    ive command line prompt utility. 
    PowerShell.exe A native command line tool used to start a Windows PowerShell session in a Command Prompt window. 
    powershell_ise.exe 
    Rhysida actors have been observed launching Windows PowerShell Integrated 
    Scripting Environment (ISE) prior to executing a malicious script (1.ps1 from a folder 
    in %AppData%\Local\Temp%). PowerShell ISE provides a graphical interface for 
    editing and testing PowerShell scripts. 
    PsExec.exe A tool included in the PsTools suite used to execute processes remotely. Rhysida actors heavily leveraged this tool for lateral movement and remote execution. 
    mstsc.exe A native tool that establishes an RDP connection to a host. 
    PuTTY.exe 
    Rhysida actors have been observed creating Secure Shell (SSH) PuTTy connections for 
    lateral movement. In one example, analysis of PowerShell console host history for a 
    compromised user account revealed Rhysida actors leveraged PuTTy to remotely 
    connect to systems via SSH. 
    PortStarter A back door script written in Go that provides functionality for modifying fi

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM008 · T1021 Remote Services · medium · draft
  The report explicitly says PsExec was used for lateral movement and remote execution, supporting the general Remote Services technique. It does not specify the underlying protocol or service mechanism.

**候选** T1021.003, T1072, T1677, T1559.002, T1210, T1569.002, T1570, T1021.002, T1588.002, T1021.005, T1021, T1195.001, T1574.001, T1105, T1550.001, T1564.001, T1528, T1187, T1608.002, T1546.012, T1053.002, T1112, T1557.001, T1124
**映射复查** The expanded candidates include specific SMB and service-execution techniques, but the behavior does not state those mechanisms. The report supports general remote service use without a defensible sub-technique.

## AA23-319A-P006

PDF 第 5 页 · observed · high · draft

**行为** Created SSH connections with PuTTY for lateral movement → remote victim systems

**上下文说明** In one example, PowerShell console history for a compromised user showed remote SSH connections.

**引文**

    Rhysida actors have been observed creating Secure Shell (SSH) PuTTy connections for 
    lateral movement. In one example, analysis of PowerShell console host history for a 
    compromised user account revealed Rhysida actors leveraged PuTTy to remotely 
    connect to systems via SSH.

**同页前后文**

    Environment (ISE) prior to executing a malicious script (1.ps1 from a folder 
    in %AppData%\Local\Temp%). PowerShell ISE provides a graphical interface for 
    editing and testing PowerShell scripts. 
    PsExec.exe A tool included in the PsTools suite used to execute processes remotely. Rhysida actors heavily leveraged this tool for lateral movement and remote execution. 
    mstsc.exe A native tool that establishes an RDP connection to a host. 
    PuTTY.exe 
    Rhysida actors have been observed creating Secure Shell (SSH) PuTTy connections for 
    lateral movement. In one example, analysis of PowerShell console host history for a 
    compromised user account revealed Rhysida actors leveraged PuTTy to remotely 
    connect to systems via SSH. 
    PortStarter A back door script written in Go that provides functionality for modifying firewall settings and opening ports to pre-configured command and control (C2) servers.[1] 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM009 · T1021.004 SSH · high · draft
  The report explicitly describes PuTTY connections used to remotely connect to systems via SSH, directly matching the SSH sub-technique.

**候选** T1563.001, T1021, T1021.008, T1098.004, T1078.001, T1550.001, T1021.004, T1070.007, T1546.004, T1552.003, T1098.001, T1070.003, T1563.002, T1547.001, T1563, T1528, T1564.006, T1021.003, T1550.004, T1547.015, T1021.007, T1564.003, T1095, T1574.011
**映射复查** The expanded candidates do not establish SSH session hijacking, authorized-key modification, or command-history clearing; only SSH remote connections are explicitly reported.

## AA23-319A-P007

PDF 第 6 页 · observed · high · draft

**行为** Extracted and dumped the NTDS database from a domain controller → Active Directory user credential hashes

**上下文说明** The advisory explicitly states Rhysida actors used ntdsutil.exe for this activity.

**引文**

    A standard Windows tool used to interact with the NTDS database. Rhysida actors 
    used this tool to extract and dump the NTDS.dit database from the domain controller 
    containing hashes for all Active Directory (AD) users.

**同页前后文**

    TLP:CLEAR 
    CISA | FBI | MS-ISAC 
    Page 6 of 20 | Product ID: AA23-319A 
    TLP:CLEAR 
    Name Description 
    secretsdump 
    A script used to extract credentials and other confidential information from a system. 
    Rhysida actors have been observed using this for NTDS dumping in 
    various instances. 
    ntdsutil.exe 
    A standard Windows tool used to interact with the NTDS database. Rhysida actors 
    used this tool to extract and dump the NTDS.dit database from the domain controller 
    containing hashes for all Active Directory (AD) users. 
    Note: It is strongly recommended that organizations conduct domain wide password 
    resets and double Kerberos TGT password resets if any indication is found that the 
    NTDS.dit file was compromised. 
    AnyDesk A common software that can be maliciously used by threat actors to obtain remote access and maintain persistence. AnyDesk also supports remote file transfer. 
    wevtutil.exe 
    A standard Windows Event Utility tool used to view event logs. Rhysid

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM010 · T1003.003 NTDS · high · draft
  The report explicitly states that actors used ntdsutil to extract and dump NTDS.dit from a domain controller, matching NTDS credential dumping.

**候选** T1003.003, T1003.005, T1556.007, T1003.002, T1003.001, T1484.001, T1552.001, T1558.001, T1003.006, T1003.008, T1207, T1558.005, T1528, T1550.003, T1486, T1555.003, T1556.005, T1558.004, T1649, T1484.002, T1484, T1003.004, T1187, T1222.001
**映射复查** The data source and extraction are explicit. No other credential dumping method is supported.

## AA23-319A-P008

PDF 第 6 页 · observed · high · draft

**行为** Cleared Windows event logs → system, application, and security logs

**上下文说明** The advisory states actors used wevtutil.exe to clear a significant number of logs.

**引文**

    A standard Windows Event Utility tool used to view event logs. Rhysida actors used this 
    tool to clear a significant number of Windows event logs, including system, application, 
    and security logs.

**同页前后文**

    in controller 
    containing hashes for all Active Directory (AD) users. 
    Note: It is strongly recommended that organizations conduct domain wide password 
    resets and double Kerberos TGT password resets if any indication is found that the 
    NTDS.dit file was compromised. 
    AnyDesk A common software that can be maliciously used by threat actors to obtain remote access and maintain persistence. AnyDesk also supports remote file transfer. 
    wevtutil.exe 
    A standard Windows Event Utility tool used to view event logs. Rhysida actors used this 
    tool to clear a significant number of Windows event logs, including system, application, 
    and security logs. 
    PowerView 
    A PowerShell tool used to gain situational awareness of Windows domains. Review of 
    PowerShell event logs identified Rhysida actors using this tool to conduct additional 
    reconnaissance-based commands and harvest credentials. 
    AZCopy A command-line utility that you can use to copy blobs or files to, from, or between Azure storage accounts. 
    StorageExplorer-
    windows-x64.exe 
    A standalone application that allows users to manage and int

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM011 · T1685.005 Clear Windows Event Logs · high · draft
  The report explicitly says actors used wevtutil to clear Windows system, application, and security event logs.

**候选** T1685.005, T1685.001, T1654, T1070.008, T1220, T1543.003, T1685, T1070.007, T1218.013, T1218.011, T1070.003, T1685.006, T1685.004, T1070.006, T1553.006, T1082, T1127.002, T1218.005, T1012, T1027.011, T1546.012, T1036.003, T1690, T1550.001
**映射复查** Direct Windows event log clearing is supported. Other log or history clearing behaviors are not.

## AA23-319A-P009

PDF 第 6 页 · observed · high · draft

**行为** Conducted domain reconnaissance and harvested credentials → Windows domain

**上下文说明** PowerShell event log review identified PowerView use for these actions.

**引文**

    A PowerShell tool used to gain situational awareness of Windows domains. Review of 
    PowerShell event logs identified Rhysida actors using this tool to conduct additional 
    reconnaissance-based commands and harvest credentials.

**同页前后文**

    ication is found that the 
    NTDS.dit file was compromised. 
    AnyDesk A common software that can be maliciously used by threat actors to obtain remote access and maintain persistence. AnyDesk also supports remote file transfer. 
    wevtutil.exe 
    A standard Windows Event Utility tool used to view event logs. Rhysida actors used this 
    tool to clear a significant number of Windows event logs, including system, application, 
    and security logs. 
    PowerView 
    A PowerShell tool used to gain situational awareness of Windows domains. Review of 
    PowerShell event logs identified Rhysida actors using this tool to conduct additional 
    reconnaissance-based commands and harvest credentials. 
    AZCopy A command-line utility that you can use to copy blobs or files to, from, or between Azure storage accounts. 
    StorageExplorer-
    windows-x64.exe 
    A standalone application that allows users to manage and interact with their cloud 
    storage. 
    Update End 
    Rhysida Ransomware Characteristics 
    Execution 
    In one investigation, Rhysida actors created two folders in the C:\ drive labeled in and out, which served 
    as a staging directory (central locat

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM012 · T1059.001 PowerShell · high · draft
  PowerShell event logs identified actors using PowerView, a PowerShell tool, for reconnaissance and credential harvesting.
- AA23-319A-PM013 · T1087.002 Domain Account · medium · draft
  The report describes PowerView use for Windows domain reconnaissance, supporting domain account discovery at medium confidence.

**候选** T1685.005, T1078.004, T1070.003, T1003.001, T1497.001, T1195.001, T1685.001, T1021, T1484.002, T1596.005, T1087.002, T1059.001, T1555, T1548.005, T1677, T1654, T1552.003, T1033, T1598.003, T1003.005, T1528, T1482, T1555.003, T1690
**映射复查** PowerShell use and domain reconnaissance are supported. Credential harvesting is stated, but the report does not identify whether credentials came from memory, files, or password stores.

## AA23-319A-P010

PDF 第 6 页 · observed · high · draft

**行为** Created staging folders and deployed tools and scripts to support encryption → victim system C drive and network

**上下文说明** The advisory identifies the in and out folders as a staging directory in one investigation.

**引文**

    In one investigation, Rhysida actors created two folders in the C:\ drive labeled in and out, which served 
    as a staging directory (central location) for hosting malicious executables. The in folder contained file 
    names in accordance with host names on the victim’s network, likely imported through a scanning tool. The 
    out folder contained various files listed in Table 2 below. Rhysida actors deployed these tools and scripts 
    to assist system and network-wide encryption.

**同页前后文**

    of 
    PowerShell event logs identified Rhysida actors using this tool to conduct additional 
    reconnaissance-based commands and harvest credentials. 
    AZCopy A command-line utility that you can use to copy blobs or files to, from, or between Azure storage accounts. 
    StorageExplorer-
    windows-x64.exe 
    A standalone application that allows users to manage and interact with their cloud 
    storage. 
    Update End 
    Rhysida Ransomware Characteristics 
    Execution 
    In one investigation, Rhysida actors created two folders in the C:\ drive labeled in and out, which served 
    as a staging directory (central location) for hosting malicious executables. The in folder contained file 
    names in accordance with host names on the victim’s network, likely imported through a scanning tool. The 
    out folder contained various files listed in Table 2 below. Rhysida actors deployed these tools and scripts 
    to assist system and network-wide encryption. 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM014 · T1074.001 Local Data Staging · high · draft
  The report says actors created a central C: drive staging directory to host malicious executables, supporting local data staging.

**候选** T1547.001, T1564.006, T1189, T1218.011, T1553.001, T1574.001, T1074.001, T1564.012, T1074.002, T1601.001, T1105, T1570, T1027.011, T1608, T1677, T1608.002, T1197, T1195.001, T1059.013, T1220, T1608.004, T1564.001, T1497.001, T1659
**映射复查** Local staging is explicit. Deployment to support network-wide encryption is reported, but the evidence does not specify how tools were transferred to other hosts.
- AI 复核 wrong_mapping · The supplied T1074.001 definition is for staging collected data locally before exfiltration. P010 describes staging malicious executables and scripts to support encryption, not staging collected victim data for exfiltration; this mapping is not supported.

## AA23-319A-P011

PDF 第 6 页 · inferred · medium · draft

**行为** Stored host-named files in the staging folder, likely imported through a scanning tool → in staging folder

**上下文说明** The advisory says the filenames were likely imported through a scanning tool.

**引文**

    as a staging directory (central location) for hosting malicious executables. The in folder contained file 
    names in accordance with host names on the victim’s network, likely imported through a scanning tool. The

**同页前后文**

    sed commands and harvest credentials. 
    AZCopy A command-line utility that you can use to copy blobs or files to, from, or between Azure storage accounts. 
    StorageExplorer-
    windows-x64.exe 
    A standalone application that allows users to manage and interact with their cloud 
    storage. 
    Update End 
    Rhysida Ransomware Characteristics 
    Execution 
    In one investigation, Rhysida actors created two folders in the C:\ drive labeled in and out, which served 
    as a staging directory (central location) for hosting malicious executables. The in folder contained file 
    names in accordance with host names on the victim’s network, likely imported through a scanning tool. The 
    out folder contained various files listed in Table 2 below. Rhysida actors deployed these tools and scripts 
    to assist system and network-wide encryption. 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM015 · T1074.001 Local Data Staging · medium · draft
  The host-named files were stored in the in folder inside the local C: drive staging directory, supporting local data staging.

**候选** T1574.001, T1027.011, T1564.009, T1074, T1074.002, T1555.004, T1074.001, T1553.005, T1564.012, T1608.002, T1105, T1197, T1124, T1677, T1080, T1119, T1601.001, T1608, T1480, T1195.001, T1220, T1570, T1176.001, T1564.006
**映射复查** The files' placement is explicit, but their import through a scanning tool is only inferred. No specific transfer mechanism is established.
- AI 复核 wrong_mapping · The supplied T1074.001 definition concerns staging collected data before exfiltration. Host-name entries in the in folder are described as scan-derived staging context, not collected victim data staged for exfiltration.

## AA23-319A-P012

PDF 第 7 页 · observed · high · draft

**行为** encrypt victim data after mapping the network → victim data

**上下文说明** The report describes Rhysida ransomware encrypting data after network mapping.

**引文**

    After mapping the network, the ransomware encrypts data

**同页前后文**

    xecutable (PE) or common object file format (COFF) 
    compiled using MinGW via the GNU Compiler Collection (GCC), which supports various programming 
    languages such as C, C++, and Go. The cryptographic ransomware application first injects the PE into 
    running processes on the compromised system. Additionally, third party researchers 
    identified evidence of Rhysida actors developing custom tools with program names set to “Rhysida-0.1”. 
    Encryption 
    After mapping the network, the ransomware encrypts data using a 4096-bit RSA encryption key with a 
    ChaCha20 algorithm. The algorithm features a 256-bit key, a 32-bit counter, and a 96-bit nonce 
    along with a four-by-four matrix of 32-bit words in plain text. Registry modification commands are 
    not obfuscated, displayed as plain-text strings and executed via cmd.exe. 
    

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM016 · T1486 Data Encrypted for Impact · high · draft
  The report directly states that ransomware encrypts victim data after mapping the network, matching data encryption for impact.

**候选** T1486, T1657, T1490, T1027.013, T1036.010, T1659, T1187, T1588.004, T1546, T1555.002, T1680, T1681, T1572, T1048.001, T1082, T1667, T1679, T1480.001, T1548.003, T1600, T1027.011, T1048.002, T1027.009, T1573.002
**映射复查** Victim data encryption is explicit. No financial theft, recovery inhibition, or content injection behavior is stated.

## AA23-319A-P013

PDF 第 8 页 · observed · high · draft

**行为** encrypt targeted files and append the ransomware extension → targeted files

**上下文说明** The report describes Rhysida ransomware file encryption.

**引文**

    encryptor runs a file to encrypt and modify all targeted files to display a .rhysida extension.

**同页前后文**

    TLP:CLEAR 
    CISA | FBI | MS-ISAC 
    Page 8 of 20 | Product ID: AA23-319A 
    TLP:CLEAR 
    Rhysida’ s encryptor runs a file to encrypt and modify all targeted files to display a .rhysida extension.[4] 
    Following encryption, a PowerShell command deletes the binary from the network using a 
    hidden command window. The Rhysida encryptor allows arguments -d (select a directory) and 
    -sr (file deletion), defined by the authors of the code as parseOptions.[5] After the lines of binary strings 
    complete their tasks, they delete themselves through the control panel to evade detection. 
    Data Extortion 
    Rhysida actors reportedly engage in “double ext

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM017 · T1486 Data Encrypted for Impact · high · draft
  The ransomware encrypts targeted victim files, directly matching Data Encrypted for Impact.

**候选** T1486, T1176.001, T1036.007, T1195.001, T1490, T1505.004, T1601.001, T1548.003, T1222, T1679, T1027.009, T1070.006, T1137.001, T1565.003, T1546.001, T1574.001, T1681, T1187, T1548.004, T1036.006, T1070.010, T1203, T1036.008, T1036.002
**映射复查** The file encryption and extension change are one impact behavior; the extension change alone does not establish masquerading.
- AI 复核 duplicate · P013 and P012 describe the same ransomware encryption behavior in the same report operation: P012 is the page 7 summary after network mapping, while P013 gives page 8 detail about target files and their extension. Retain one behavior with the more specific evidence.

## AA23-319A-P014

PDF 第 8 页 · observed · high · draft

**行为** delete the ransomware binary after encryption → ransomware binary

**上下文说明** The report describes post-encryption binary deletion through PowerShell.

**引文**

    a PowerShell command deletes the binary from the network

**同页前后文**

    TLP:CLEAR 
    CISA | FBI | MS-ISAC 
    Page 8 of 20 | Product ID: AA23-319A 
    TLP:CLEAR 
    Rhysida’ s encryptor runs a file to encrypt and modify all targeted files to display a .rhysida extension.[4] 
    Following encryption, a PowerShell command deletes the binary from the network using a 
    hidden command window. The Rhysida encryptor allows arguments -d (select a directory) and 
    -sr (file deletion), defined by the authors of the code as parseOptions.[5] After the lines of binary strings 
    complete their tasks, they delete themselves through the control panel to evade detection. 
    Data Extortion 
    Rhysida actors reportedly engage in “double extortion”—demanding a ransom payment to decrypt 
    victim data and threatening to publi

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM018 · T1070.004 File Deletion · medium · draft
  The report describes deleting the ransomware binary after encryption, consistent with File Deletion to remove an artifact.

**候选** T1485.001, T1485, T1070.004, T1490, T1036.010, T1070.003, T1218.014, T1102.001, T1556.005, T1680, T1486, T1657, T1105, T1681, T1080, T1601.001, T1546.017, T1053.005, T1685.005, T1552.003, T1070.010, T1546.014, T1195.001, T1659
**映射复查** This is deletion of the ransomware binary after its task, not destruction of victim data or inhibition of recovery.

## AA23-319A-P015

PDF 第 8 页 · observed · medium · draft

**行为** delete completed binary strings to evade detection → binary strings

**上下文说明** The report attributes self-deletion after task completion to evasion; the referent of “they” is described in the ransomware characteristics section.

**引文**

    they delete themselves through the control panel to evade detection.

**同页前后文**

     ID: AA23-319A 
    TLP:CLEAR 
    Rhysida’ s encryptor runs a file to encrypt and modify all targeted files to display a .rhysida extension.[4] 
    Following encryption, a PowerShell command deletes the binary from the network using a 
    hidden command window. The Rhysida encryptor allows arguments -d (select a directory) and 
    -sr (file deletion), defined by the authors of the code as parseOptions.[5] After the lines of binary strings 
    complete their tasks, they delete themselves through the control panel to evade detection. 
    Data Extortion 
    Rhysida actors reportedly engage in “double extortion”—demanding a ransom payment to decrypt 
    victim data and threatening to publish the sensitive exfiltrated data unless the ransom is paid.[4],[6] 
    Rhysida actors direct victims to send ransom payments in Bitcoin to cryptocurrency wallet addresses 
    provided by the threat actors. As shown in Figure 1, Rhysida ransomware drops a ransom note named 
    “CriticalBreachDetected” as a PDF

**自动验证** 引文、页码、偏移和正式契约均通过。

- AA23-319A-PM019 · T1070.004 File Deletion · medium · draft
  The report describes completed binary strings deleting themselves to evade detection, consistent with File Deletion to remove artifacts.

**候选** T1053.005, T1205, T1564.014, T1218.002, T1485.001, T1485, T1222.002, T1218.011, T1222, T1027.010, T1070.004, T1578.003, T1574.005, T1480.001, T1055.013, T1070.010, T1666, T1548.002, T1574.001, T1027.013, T1027.015, T1480, T1055.001, T1070.003
**映射复查** File Deletion fits better than Control Panel, which does not describe this deletion behavior.

## AA23-319A-P016

PDF 第 8 页 · inferred · medium · draft

**行为** use double extortion by demanding payment and threatening to publish exfiltrated data → victim data

**上下文说明** The advisory attributes this extortion pattern to Rhysida actors based on cited reporting.

**引文**

    double extortion

**同页前后文**

    extension.[4] 
    Following encryption, a PowerShell command deletes the binary from the network using a 
    hidden command window. The Rhysida encryptor allows arguments -d (select a directory) and 
    -sr (file deletion), defined by the authors of the code as parseOptions.[5] After the lines of binary strings 
    complete their tasks, they delete themselves through the control panel to evade detection. 
    Data Extortion 
    Rhysida actors reportedly engage in “double extortion”—demanding a ransom payment to decrypt 
    victim data and threatening to publish the sensitive exfiltrated data unless the ransom is paid.[4],[6] 
    Rhysida actors direct victims to send ransom payments in Bitcoin to cryptocurrency wallet addresses 
    provided by the threat actors. As shown in Figure 1, Rhysida ransomware drops a ransom note named 
    “CriticalBreachDetected” as a PDF file—the note provides each company with a unique code and 
    instructio

**自动验证** 引文、页码、偏移和正式契约均通过。


**候选** T1657, T1070.006, T1195.001, T1564.004, T1027.006, T1684.002, T1530, T1666, T1559.002, T1595.003, T1681, T1667, T1187, T1082, T1485.001, T1218.011, T1684.001, T1027.011, T1564.009, T1677, T1596.004, T1608.004, T1597.001, T1597.002
**映射复查** The reported demand and threat to publish data describe extortion, but none of the supplied ATT&CK definitions directly represents this coercive behavior. Do not force-map it to Financial Theft or data theft.

## AA23-319A-P017

PDF 第 8 页 · observed · high · draft

**行为** direct victims to pay ransom in Bitcoin → ransom payment

**上下文说明** The advisory describes the ransom payment direction given to victims.

**引文**

    Rhysida actors direct victims to send ransom payments in Bitcoin

**同页前后文**

    ts -d (select a directory) and 
    -sr (file deletion), defined by the authors of the code as parseOptions.[5] After the lines of binary strings 
    complete their tasks, they delete themselves through the control panel to evade detection. 
    Data Extortion 
    Rhysida actors reportedly engage in “double extortion”—demanding a ransom payment to decrypt 
    victim data and threatening to publish the sensitive exfiltrated data unless the ransom is paid.[4],[6] 
    Rhysida actors direct victims to send ransom payments in Bitcoin to cryptocurrency wallet addresses 
    provided by the threat actors. As shown in Figure 1, Rhysida ransomware drops a ransom note named 
    “CriticalBreachDetected” as a PDF file—the note provides each company with a unique code and 
    instructions to contact the group via a Tor-based portal. 
     
    Figure 1: Rhysida Ransom Note 
    Identified in analysis and listed in open-source reporting, the contents of the ransom note are embedded 
    as plain-text in the r

**自动验证** 引文、页码、偏移和正式契约均通过。


**候选** T1666, T1496.003, T1583.008, T1657, T1598.003, T1684.001, T1598, T1684.002, T1681, T1659, T1684, T1480.001, T1683.001, T1485.001, T1027.018, T1195.001, T1559.002, T1683, T1601.001, T1218.011, T1574.011, T1683.002, T1486, T1667
**映射复查** Directing victims to pay ransom in Bitcoin is an extortion payment demand, not evidence of financial theft by the actors through a technique represented in the supplied candidates.

## AA23-319A-P018

PDF 第 8 页 · observed · high · draft

**行为** drop a PDF ransom note → compromised system

**上下文说明** The ransom note includes a unique code and contact instructions, which are not repeated here.

**引文**

    Rhysida ransomware drops a ransom note named

**同页前后文**

    eir tasks, they delete themselves through the control panel to evade detection. 
    Data Extortion 
    Rhysida actors reportedly engage in “double extortion”—demanding a ransom payment to decrypt 
    victim data and threatening to publish the sensitive exfiltrated data unless the ransom is paid.[4],[6] 
    Rhysida actors direct victims to send ransom payments in Bitcoin to cryptocurrency wallet addresses 
    provided by the threat actors. As shown in Figure 1, Rhysida ransomware drops a ransom note named 
    “CriticalBreachDetected” as a PDF file—the note provides each company with a unique code and 
    instructions to contact the group via a Tor-based portal. 
     
    Figure 1: Rhysida Ransom Note 
    Identified in analysis and listed in open-source reporting, the contents of the ransom note are embedded 
    as plain-text in the ransom binary, offering network defenders an opportunity to deploy string-based 
    detection for alerting on evidence of the ransom note.

**自动验证** 引文、页码、偏移和正式契约均通过。


**候选** T1553.003, T1486, T1564.006, T1490, T1601.001, T1055.009, T1583.001, T1650, T1059.002, T1679, T1497.001, T1036.010, T1027.016, T1574.005, T1689, T1036.002, T1548.002, T1055.011, T1684.002, T1548.003, T1543.003, T1564.001, T1480.001, T1518.001
**映射复查** Dropping a ransom note is part of the ransomware operation, but none of the supplied techniques specifically describes note delivery. The evidence does not support a more specific technique.

## 待核实的证据

引文有误的候选可在 evidence_decisions 中编辑、拒绝或标记证据不足。

## 全局审核意见

- P012/P013 are a cross-page duplicate that an automatic resolver may miss because the pages and quote detail differ. Keep the encryption behavior once with the more specific P013 evidence; do not treat the .rhysida suffix as a separate occurrence.
- P001 and P002 both mention VPN access, but P001 specifies authentication with compromised valid credentials while P002 also includes RDP connections and summarizes living-off-the-land activity. Their text does not establish the same host or occurrence, so do not drop either wholesale.
- P010 describes staging directories and deployment of tools and scripts. P011 separately infers that host-named files in the in folder were imported through scanning; the report does not explicitly say actors stored those files. Preserve P011 as an inference or remove it if actor placement is required, and do not collapse it into the staging-directory action.
- P014 describes PowerShell deletion of the ransomware binary after encryption; P015 separately describes binary strings deleting themselves after completing tasks. Different objects and stated purposes mean these are not duplicates.
- P016 captures the reported double-extortion demand and threat to publish data; P017 separately describes instructions to pay in Bitcoin. Preserve the extortion behavior and payment-channel detail without conflating them.
-  · missed_behavior · Page 7 states that the cryptographic ransomware application injects its executable into running processes on compromised systems. This process-injection behavior is not represented in the inventory.
-  · missed_behavior · Page 7 states that registry modification commands were executed via cmd.exe. The inventory has no row for the reported registry modification behavior.

## 已确认样本的独立对照


逐条提议、处置和去重明细见 annotation_audit.json。
