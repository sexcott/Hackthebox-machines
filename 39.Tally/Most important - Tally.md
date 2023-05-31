## Tecnicas utilizadas
-   SharePoint Enumeration
-   Information Leakage
-   Playing with mounts (cifs, curlftpfs)
-   Abusing Keepass
-   Abusing Microsoft SQL Server (mssqlclient.py - xp_cmdshell RCE)
-   Abusing SeImpersonatePrivilege (JuicyPotato)
## Procedimiento
- Fuzzing directories web
- Crear una montura del servicio FTP de la maquina victima para ahorrarnos tiempo, usaremos la herramienta **curlftpfs**
- Romper por fuerza brueta la contraseña del keepass con keepass2john
- Crear una montura para el recurso compartido a nivel de red con **mount** ``mount -t cifs //$ip/$recurso /create/to/path -o  username=$username,password=$password,rw
- Information Leaked SQL credentials, nos conectamos al MSSQL de la maquina con la herramienta que viene por defecto en Impacket; **mssqlclient.py**
- Habilitamos el xp_cmdshell y nos entablamos una reverse shell por powershell con el repositorio de nishang.
- Escalamos privilegios con JuicyPotatoNG de **Antonio Coco** 