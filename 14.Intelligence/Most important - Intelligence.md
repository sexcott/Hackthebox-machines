- Descargar el documento encontrado en el domino **HTTP**
- Indagar por los metadatos del archivo
- Fuzzear entre la fecha de los documentos para encontrar nuevos usuarios
- *Bash scripting*
![[Pasted image 20221028175711.png]]
- Extraer los creadores de los documentos con exiftool
- Validar usuarios validos del dominio con kerbrute ``kerbrute enumuser -d $domain --dc $domain $userList``
- Intentar hacer un ASREProast attack
- Extrar informacion de pdf. Convertir lo que hay en el pdf a texto con **pdftotext** 
- *Bash scripting*
![[Pasted image 20221028182810.png]]
- Validar la contraseña encontrada con crackmapexec entre todos los usuarios
- Una vez encontado el usuario para la contraseña, intentar un Kerberoasting attack para conseguir un TGS
- Intentar conectase a travez de RPC con las contraseñas encontradas 
- Enumerar grupos con ``enumdomgroups
- Cada grupo tiene un **RID**, se puede enumerar los usuario de este con ``querygroupemem $RID`` y posteiormente inspeccionar el usuario con ``queryuser $RID
- Utilizar el repositorio de s4vitar(**RPCenum**)
- Dumpear la infomacion de Domain Controller con ldapdomainenum
- Con las credenciales obtenidas, listar los recursos compartidos a nivel de red con smb
- Del script en PowerShell, intentar aprovecharse de la tarea que se ejecuta en intervalos regulares de tiempo.
- Uso de **Responder** con dnstool.py
![[Pasted image 20221028192517.png]]
- Comprobar las credenciales con **crackmapexec** 
- Dumpear la informacion con bloodhound-python
- Importar la informacion a bloodhound
- Marcar los usuarios pwned! 
- Tirar de **gmsadumper**
- Con la contraseña encontrada, usar herramienta getST.py
- Tirar de pywerview para dumpear el snp
![[Pasted image 20221028195739.png]]
- Sincronizar la hora, a la hora de la maquina con ntpdate
- Con getst, impersonamos al usuario adminstrador, de la siguiente manera
![[Pasted image 20221028200031.png]]
- Crear una variable de entorno que se llame ``export KRB5CCNAME=Administrator.ccache``
- agregar al /etc/hosts el dc
- Autenticarnos con wmiexect.py de la siguiente manera -> ``wmiexec.py $domainController -k --no-pass``