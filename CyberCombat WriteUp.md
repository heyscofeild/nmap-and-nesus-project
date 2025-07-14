# Nmap

-   Network Discovery: scan networks and discover devices in them
-   Port scanning: determines which ports/services are open and used
-   OS Fingerprinting: nmap can attempt to identify the OS running on a target
-   Vulnerability Assessment: identify potential vulnerabilities

# Nessus

-   Scans for security vulnerabilities in devices/applications/OS...
-   Nessus identifies software flaws, missing patches, malware and misconfiguration errors

# Nessus vs Nmap

-   Nessus is often considered to be similar to NMAP, but it really is capable of so much more. It can do things like credential scanning which is when we actually have an account that has privileges, which are usually administrator privileges so that we can log in and run system checks.

## Nmap

before everything read this report while watching the simulation,here is the link :(send the request and i will accept)
https://drive.google.com/drive/folders/17o3G7TuaGohqi4TuNeLJlqyRJ5L9caFy?usp=sharing

for beggining with mt lab have windows xp professional and metasploitable2.

1-so to begin with i will start by using ifconfig so i to get to know my lab subnet ,this is the result:
192.168.83.0/24

2-i will do a host scan and store it in a folder with a some simple parsing:

nmap -sn 192.168.83.0/24 -oG - | grep Up | awk '{print $2}' > live_hosts.txt

this is the result:
192.168.83.1
192.168.83.2
192.168.83.128
192.168.83.130
192.168.83.254
192.168.83.129

so without including the vmware ip's and this specific machine wici is kali i am left with these two:
192.168.83.128 (metasploitable2)
192.168.83.130 (windows XP)

3-now i will do a simple scan on those ip's i wanted to do an agressive scan with -T5 but one of the host isnt giving me results because of it so i am using ht edefault speed:

nmap -A -iL live_hosts.txt

the results are shown in the recording.

4- now here i will be scaning by using some stealthy methods :

nmap -sS -A -D 192.168.1.100,192.168.1.200,ME,192.168.83.129 192.168.83.128 for decoys
nmap -sS -A -f 192.168.83.128

i can also limit my speed but its a waste of time.

the result is shown in the reccording.

5-now using scripts i will do these 4 to learn more about those open service ports:

nmap --script=http-title,http-methods --script-args http.proxy=http://172.67.142.200:80 -p 80 192.168.83.128
nmap --script=ftp-anon -p 21 192.168.83.128
nmap --script=mysql-info -p 3306 192.168.83.128
nmap --script=smb-vuln-ms17-010,smb-vuln-conficker -p 139,445 192.168.83.130

6- now i will run all the vulnerability scanners that are avaliable on nse :

nmap --script=vuln 192.168.83.128

7- in the end i will exploit those vulnerabilities by the following scripts:

nmap --script=http-shellshock -p 80 192.168.83.128
nmap --script=smb-vuln-ms17-010 -p 139,445 192.168.83.130
nmap --script=ftp-proftpd-backdoor -p 21 192.168.83.128
nmap --script=mysql-empty-password -p 3306 192.168.83.128

# Nmap important write up

A- in this part of the write up i will be covering most of the operations and things that nmap can do under a sequence of commands so that it could be more enjoyable to read than something resembling to a documentation:

1-i use ifconfig to get my ip subnet so that i can scan the devices connected to my lan.

2-after that i will use nmap with flag -sn and give it the subnet, and i will outpu the result in a file by using the -o so i can rescan all the ip that i got.
#but instead of only using -sn and -o i will also add some piping tha will save the ip's in a foramt readable for nmap to input, with the following comaand:

-   before i begin i could use the -oX to outpuy it in the xml fromat and then manipulate it and parse it with perl, but i prefer using the -oG wich is the grapable format such that its esier to parse and manipulate it directly in the command line.

nmap -sn '.'.'.0/24 -oG - | grep Up | awk '{print $2}' > live_hosts.txt

-   the - after the -oG will sent the output to the terminal instead of a file.
    for note the oG flag outputs the data in this foramt:
    Host: 192.168.1.1 () Status: Up - So after that the pipe will take the outpu to grep who will filter only the the lines that have the Up notation meaning the live hosts.

-after that the last pipe will take the live hosts to the awk command that will take only the selected columns.

-finally i will redirect the outpu to my file.
example:
nmap -sn '.'.'.0/24 -oG - | grep Up | awk '{print $2}' > nmaphosts.txt

3-after that i will use the following scan:

nmap -A -t5 '.'.'.'

instead of using these following flags to get their respective informations:
-p to get all ports
-sV to get service and version
-O to get operationg system
--traceroute for the route but hile i am on a lan so its usless

i will use -A that will execute all of them.

an i will use the -t5 flag so i can set the agressivity to max for the time factor.

4- for evading ids and firewals i would use some of this flags :
-f that will fragment the packets more.
-D that will use decoys that we set in the command.

-   and i will also use a -t2 or -t3 flag so i can be less agressive and detectable.
    --proxies that will Relay connections through HTTP/SOCKS4 proxies (here the --traceroute flag would be good since it will leave my lan and come back)
    --badsum Send packets with a bogus TCP/UDP/SCTP checksum

adn we can also make advantage of the different scan techiniques to evade firewals example:
-sU for UDP scan
-sI for idle scan
-sS for a full TCP port scan to find open ports.
ect..

B- the use of scripts :
so in nmap we have variant types of scripts they all fall under nmap script engine (NSE) for short we can create our own scripts by writing them lua language and having the extension .nse , to use them we do:

-the --script flag.
-and also for the default ones wich we can use -sC for them instead of --script=default.

and we have specified categories like:

-   auth:These scripts deal with authentication credentials (or bypassing them) on the target system, like x11-access, ftp-anon, and oracle-enum-users.

-   broadcast:Scripts in this category typically do discovery of hosts not listed on the command line by broadcasting on the local network, like broadcast-dhcp-discover and broadcast-dhcp6-discover.

-   brute:These scripts use brute force attacks to guess authentication credentials of a remote server ,like ttp-brute, oracle-brute, snmp-brute.

-   discovery: These scripts try to actively discover more about the network by querying public registries, SNMP-enabled devices, directory services, and the like,Examples include html-title (obtains the title of the root path of web sites), smb-enum-shares (enumerates Windows shares), and snmp-sysdescr (extracts system details via SNMP).

-   dos: Scripts in this category may cause a denial of service. Sometimes this is done to test vulnerability to a denial of service method, but more commonly it is an undesired by necessary side effect of testing for a traditional vulnerability. These tests sometimes crash vulnerable services.

and many others like: exploit, external, fuzzer, intrusive, malware, safe, vuln ect...

i can use the following sequence since it would be a great example:

1-nmap -sn '.'.'.0/24
for dicovering different scripts.

2-nmap -sS -p- --min-rate=5000 '.'.'.'  
(-p) for scaning all ports
(-sS) for tcp syn scan wich is also called half open scan.
(--min-rate=5000) wich sends packets no slower then 5000 per seconf.

3-nmap --script=http-title,http-methods -p 80 '.'.'.'(for http)

nmap --script=ftp-anon -p 21 '.'.'.' (for ftp)

nmap --script=smb-enum-shares,smb-os-discovery -p 139,445 '.'.'.' (for smb)

nmap --script=mysql-info -p 3306 '.'.'.' (for mysql)

-   i will use these scripts wich are enumeration scripts wich fall under many categories (auth,safe,default..) so that i learn more about the services and the ports 80,21.445,3306 are all default ports that i specified that will work with their following service.

4-nmap --script=vuln
the ni will run general vulnerability scripts.

5- here i can use something like metasploit framwork since i learned the vulnerabilities or i could use some simple vulnerability scripts wich are included in nse, example:

nmap --script=http-shellshock -p 80 '.'.'.'  
nmap --script=smb-vuln-ms17-010 -p 139,445 '.'.'.'  
nmap --script=ftp-proftpd-backdoor -p 21 '.'.'.'  
nmap --script=mysql-empty-password -p 3306 '.'.'.'

This write up covers most of nmap aspects under different implementations, all the following categories were implemented at least once:

HOST DISCOVERY, SCRIPT SCAN, SERVICE/VERSION DETECTION, PORT SPECIFICATION AND SCAN ORDER, SCAN TECHNIQUES, TIMING AND PERFORMANCE , OS DETECTION, FIREWALL/IDS EVASION AND SPOOFING, OUTPUT,TARGET SPECIFICATION, and MISC options.
most of the informations presented are gathered from various sources :
man nmap (in the command line)
nmap -h
https://nmap.org/book/man.html
https://nmap.org/book/toc.html
and some from comunity forums.

## Neesus

### Basic Scan

-   Here i have started a basic network scan of my home network and as you can see has returned critical errors from my router (192.168.1.1) and kali vm ware machine (.42)
    <img width="928" height="455" alt="image" src="https://github.com/user-attachments/assets/e5805295-28e9-44bc-94d3-d1036b227354" />

-   The router has a critical error indicating the MiniUPnP which is a plug-n-play technology is inferior to 1.4 and must be upgraded because of: - An out of bounds read error - Buffer overflow
    <img width="927" height="414" alt="image" src="https://github.com/user-attachments/assets/2012f062-8348-4a03-8820-e8922c92b1a2" />

-   However, my kali machine indicates a deprecated node version (inferior to 18.19.1), which is subject to multiple vulnerabilities specified in the description
    <img width="929" height="429" alt="image" src="https://github.com/user-attachments/assets/c96a0818-5b9e-4134-9174-16ab08df4b9c" />

### Credentialed Scan

-   We have done a credentialed network scan which, compared to a normal scan, has access inside the system, not just what’s visible from the network gives us privileged
-   Install and setup SSH with these commands on linux:

```
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

-   Configure the scan:
    <img width="720" height="553" alt="image" src="https://github.com/user-attachments/assets/04c951c5-5cfe-42c7-89f7-241107a9d3be" />

-   We have performed the scan and got multiple results as shown below
    <img width="928" height="380" alt="image" src="https://github.com/user-attachments/assets/fef4c7d5-f6f6-43fe-85ba-0b7893f99160" />

-   One of them has a critical error, which appears to be the same deprecated node error shown above

## Nessus Metasploitable Scan

-   In this section, we will use Nessus to perform a vulnerabilities on a metasploitable VM

### Lab Setup

-   Virtual machine running Kali linux, with Nessus installed.
-   Virtual machine with metasploitable2 running.
-   Both VM's belong to the same Virtual Network "VMNet0" with IP address $192.168.214.0$ to allow communication between them.

#### Basic Host Discovery Scan

-   The first scan to run is a basic host scan to identify the available hosts on the network.
-   We choose the Virtual Network's IP address, and then configure Nessus to scan the common ports.
    <img width="782" height="450" alt="Pasted image 20250714222624" src="https://github.com/user-attachments/assets/e52a3a1f-2745-4de0-8794-58174634cf59" />

-   This is the result of the scan
    <img width="1528" height="399" alt="Pasted image 20250714222517" src="https://github.com/user-attachments/assets/710e2fab-04d8-4bec-8816-03830556727e" />

-   Notice how there is an IP address with many open ports. That happens to be the IP Address of the VM running metasploitable.

#### Vulnerabilities Scan

-   The first scan that we're going to run is going to be uncredentialled, meaning that we won't give credentials to allow Nessus to connect to the metasploitable machine.
-   After identifying the target machine. We can now perform a basic vulnerabilities scan.
-   When creating a new scan. Select the 'Advanced Scan' option.
-   Nessus has many configuration options for the scan in-order to tailor it to your needs.
    <img width="204" height="358" alt="Pasted image 20250714224148" src="https://github.com/user-attachments/assets/dccda90d-e08b-4bea-9658-bb4fff2ad62a" />

-   We won't go through all of them here, but we will go through some ones.
-   Under assessment category, we will enable both Web Applications and Malware scans.
    <img width="1378" height="551" alt="Pasted image 20250714224559" src="https://github.com/user-attachments/assets/7de986a7-c9e9-4bda-8ff2-5f27d6d7f045" />

-   Enable Web Application Scan
    <img width="1557" height="623" alt="Pasted image 20250714224636" src="https://github.com/user-attachments/assets/02e1b7ec-1885-474d-b1fe-e0d9d1562646" />

-   We can skip the credentials section for now. Let's see what vulnerabilities Nessus can detect without being given access to the machine.
-   Save the changes, and then launch the scan.
-   After the scan is finished, we get a list vulnerabilities
    <img width="1517" height="390" alt="Pasted image 20250714223732" src="https://github.com/user-attachments/assets/24090def-7ec2-434f-9a21-7d7408cf9703" />

<img width="1205" height="703" alt="Pasted image 20250714223746" src="https://github.com/user-attachments/assets/db341204-e88a-4581-8053-f21479ad518e" />

-   Lets take a closer look at one of those vulnerabilities.
    <img width="1190" height="453" alt="Pasted image 20250714225413" src="https://github.com/user-attachments/assets/5b9045e1-94ee-4fcd-a69c-98d12ecbd211" />

-   A VNC (Virtual Network Computing) server is software that allows remote control of another computer.
-   Due to the weak password used, any attacker can login into the server and control the victim's machine easily.

#### Credentialed Vulnerabilities Scan

-   This time, to allow Nessus to perform a deeper scan, we will provide SSH credentials to allow it to login to the target machine.
-   Go to credentials tab, and add a new SSH authentication.
-   Set the authentication method to be password
-   Enter metasploitable's username and password `msfadmin/msfadmin`
-   <img width="1401" height="681" alt="Pasted image 20250714225822" src="https://github.com/user-attachments/assets/e9105e4e-c8b8-48fe-942f-3922c72ea5d5" />
-   Save the changes and then run the scan again.
    <img width="1208" height="173" alt="image" src="https://github.com/user-attachments/assets/720a81db-7145-410b-a1a4-234c991f1239" />
    <img width="1199" height="704" alt="image" src="https://github.com/user-attachments/assets/44e1d884-dad3-463e-bda7-08ca3f2874f1" />
-   We can see that the credentialed scan has discovered even more vulnerabilities.
