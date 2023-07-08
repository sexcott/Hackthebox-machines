----------
- Tags: #NVMS-1000 #directory-transversal #port-forwarding #NSClient
------
## Técnicas utilizadas
- NVMS-1000 Exploitation - Directory Traversal  
- Local File Inclusion (LFI)  
- Local Port Forwarding - SSH  
- NSClient++ Exploitation - Privilege Escalation
## Procedimiento

![[Pasted image 20230626135735.png]]

#### Reconocimiento

El escaneo con **nmap** nos da como resultado los siguientes puertos:
```java
# nmap -sCV -p21,22,80,135,139,445,5666,6063,6699,8443,49664,49665,49666,49667,49668,49669,49670 10.10.10.184 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-26 14:03 MST
Nmap scan report for 10.10.10.184
Host is up (0.13s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
22/tcp    open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 c71af681ca1778d027dbcd462a092b54 (RSA)
|   256 3e63ef3b6e3e4a90f34c02e940672e42 (ECDSA)
|_  256 5a48c8cd39782129effbae821d03adaf (ED25519)
80/tcp    open  http
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|     AuthInfo:
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|_    </html>
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5666/tcp  open  tcpwrapped
6063/tcp  open  x11?
6699/tcp  open  napster?
8443/tcp  open  ssl/https-alt
| http-title: NSClient++
|_Requested resource was /index.html
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|_    Location: /index.html
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.93%I=7%D=6/26%Time=6499FD13%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nCon
SF:tent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xe
SF:f\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\
SF:x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-tra
SF:nsitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtm
SF:l\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<s
SF:cript\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20w
SF:indow\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20
SF:</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(HTTPOption
SF:s,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nContent-
SF:Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\xbb
SF:\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Tr
SF:ansitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-transiti
SF:onal\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\
SF:r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<script
SF:\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20window
SF:\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</scr
SF:ipt>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RTSPRequest,1B4
SF:,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nContent-Lengt
SF:h:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\xbb\xbf<
SF:!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Transit
SF:ional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-transitional\
SF:.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\r\n<h
SF:ead>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<script\x20t
SF:ype=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20window\.loc
SF:ation\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</script>\
SF:r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(FourOhFourRequest,65
SF:,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-type:\x20text/html\r\nCon
SF:tent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=6/26%Time=6499FD1A%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\0s\0d\0a\0y\0:\0T\0h\0u\0:\0T\0h\0u\0r\0s\0")%r(HTTPOption
SF:s,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\
SF:x20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404\r\nContent-Length:\
SF:x2018\r\n\r\nDocument\x20not\x20found")%r(RTSPRequest,36,"HTTP/1\.1\x20
SF:404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(SIPOpt
SF:ions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20n
SF:ot\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-06-26T21:01:14
|_  start_date: N/A
|_clock-skew: -4m08s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.30 seconds
```

Si lanzamos un **whatweb** sobre el sitio web, podemos ver las tecnologías que corren por detras:
```ruby
# whatweb 10.10.10.184
http://10.10.10.184 [200 OK] Country[RESERVED][ZZ], IP[10.10.10.184], Script[text/javascript], UncommonHeaders[authinfo]
```

--------
#### NVMS-1000 Exploitation - Directory Traversal

La version actual de **NVMS** tiene una vulnerabilidad de tipo **Local File inclusion** con un **Path Tranversal**. Podemos usar esta vulnerabilidad para leer las contraseñas que esta en el directorio de **Nathan** ( Sabemos esto gracias los *.txt* encontrados en el servicio **ftp** ).

----------------------------------------------------
#### Local Port Forwarding - SSH

Podemos intentar un ataque de fuerza bruta contra el servicio de **SSH** ya que que esta abierto con los usuarios encontrados en los archivos del **ftp** y encontramos la contraseña para uno de ellos. Hare un Port Forwarding del puerto **8443** que es del **NSClient ++**, ya que cuando intentamos logearnos con cualquier usuario nos mandama un **403 Not Allowed** que podria ser que no tenemos disponibilidad al recurso desde nuestro host.

Una vez hacemos el port forwarding, ingresamos a la pagina. Si vamos al apartado de recuperar contraseña, encontramos un comando para poder listar las contraseñas. Si encontramos el binario correspondiente y lo ejecutamos como se nos indica, podemos dumpear las contraseñas.

---------
#### NSClient++ Exploitation - Privilege Escalation

Podemos aprovecharnos de una vulnerabilidad de la versión actual para ejecutar comandos de manera remota.
Seguir los pasos encontrados en **exploitdb**.

