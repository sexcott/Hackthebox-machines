------------
- Tags: #API-Enumeration  #Abusing-API  #JWT
------------
## Tecnicas utilizadas
- API Enumeration  
- Abusing API - Registering a new user  
- Abusing API - Logging in as the created user  
- Enumerating FastApi Endpoints through Docs  
- Abusing FastAPI - We managed to change the admin password  
- Abusing FastAPI - We get the ability to read files from the machine (Source Analysis)  
- Creating our own privileged JWT  
- Abusing FastAPI - We achieved remote command execution through the exec endpoint  
- Information Leakage (Privilege Escalation)
---------------
## Procedimiento
![[Pasted image 20230603111144.png]]
- Comenzamos haciendo fuzzing en toda la api para ir sacando rutas existentes. Despues probando fuzzear con los metodos.
- Aprovechamos que se puede cambiar la contraseña de cualquier usuario solo proporcionando su "GUID" para cambiarsela al usuario admin@admin.htb. Con esto conseguimos logueando como admin en la ruta de la api `/api/v1/user/login`. Se nos proporciona un Json Web Token con el cual podremos acceder a leer archivos del equipo de manera romata y tambien ejecutar comandos en la ruta `/api/v1/admin/exec/$comando`. Cabe recalcar, que la pagina principal de los EndPoints("Docs") no funciona, ni con el JWT del admin ni con la de un usuario cualquiera.
- La escala de privilegios es facil, la contraseña del usario ROOT se encuentra en un archivo de autentificacion `auth.log` en la carpeta principal del proyecto