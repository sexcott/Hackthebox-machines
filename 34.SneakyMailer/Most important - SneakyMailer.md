
## Tecnicas utilizadas
- Information Leakage  
- Mass Emailing Attack with SWAKS  
- Password Theft  
- Abusing Pypi Server (Creating a Malicious Pypi Package)  
- Abusing Sudoers Privilege (Pip3)
## Procedimiento
- Virtual Hosting
- Recoleción de información
- Envio de correos masivos con **Swaks**. Abrimos un servidor con *netcat* para ver la data que nos estan tramitando por *POST*
- Information Leaked en la bandeja de correo del usuario. Credenciales encontradas para autenticarnos en **FTP**.
- *Directory Fuzzing* & *Vhost Fuzzing* para encontrar la raiz en la que tenemos permiso de escritura desde **FTP**.
- Subimos una web shell y nos entablamos una reverse shell para acceder a la maquina victima.
- Listar procesos del sistema con **Ps -faux**. Password Leaked & cracking password with John.
- Como se emplea **Virtual Hosting** y esta por detras *Nginx*, listamos la ruta ``/etc/nginx/sites-avalible/`` para ver si existen más subdominios.
- Reutilización de contraseñas en el *basic authentication* de la pagina web de Pypi.
- Creamos un Private Python Package repository con una revershell incluida(se define en el _setup.py_). Creamos tambien un .pypirc con lo definido en el manual.
![[Pasted image 20221210153537.png]]
- Subimos nuestro repositorio a la maquina victima con el comando explicado en el manual. Nos entabamos una reverse shell primero a nuestra maquina, abrimos otra seccion de Netcat, nos salimos de la primera y ya tendriamos una shell en la maquina victima como el usuario *low*.
- Miramos los privilegios que tenemos como usuario. Nos aprovechamos de Pip3 con las instrucciones de GTObins
