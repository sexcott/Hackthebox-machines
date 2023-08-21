---------
- Tags #information-leakage #moodle #wfuzz-enumeration #password-crack #cron-job 
- -------
## Técnicas utilizadas
- information Leakage  
- Abusing Moodle - Login BruteForce (Wfuzz)  
- Moodle Exploitation - Code Injection (Abusing Math formulas in Quiz component) [RCE]  
- Database Enumeration  
- Cracking Hashes  
- Abusing Cron Job [Privilege Escalation]
## Procedimiento

![[Pasted image 20230817183722.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos ver los siguientes puertos abiertos, asi como los servicios y sus respectivas versiones:
```ruby
# nmap -sCV -p80 10.10.10.153 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-17 20:30 UTC
Nmap scan report for 10.10.10.153
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Blackhat highschool
|_http-server-header: Apache/2.4.25 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.85 seconds
```

Un escaneo con **whatweb** nos muestra las siguentes tecnologías corriendo por detrás del sitio web:
```ruby
# whatweb 10.10.10.153
http://10.10.10.153 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], Email[contact@blackhatuni.com], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.153], JQuery[1.11.1], Script, Title[Blackhat highschool]
```

-----------
#### Information Leakage 
Dentro de la pagina principal, no hay nada que podamos hacer, nada interesante. Si atentamos contra los directorios, vemos que tenemos capacidad de directory listing en uno de nombre **Imagenes**:
![[Pasted image 20230817203353.png]]

Si vamos recorriendo una por una, podemos llegar a visualizar una que se excede de tamaño de memoria (a comparacion de las imagenes):
![[Pasted image 20230817203410.png]]

Descargaremos la imagen en nuestra maquina para inspeccionarla, Si le hacemos un **File** al archivo, vemos que en realidad, es un archivo de texto:
```ruby
# file 5.png
5.png: ASCII text
```

El archivo contiene un mensaje de **Giovanni** el cual, puede ser un usuario potencial a nivel de sistema o a nivel de web:
```
Hi Servicedesk,

I forgot the last charachter of my password. The only part I remembered is Th4C00lTheacha.

Could you guys figure out what the last charachter is, or just reset it?

Thanks,
Giovanni
```

----------------
#### Abusing Moodle - Login BruteForce (Wfuzz)  
El mensaje nos dio una gran pista acerca de una posible contraseña para un usuario de una pagina. Solo nos queda saber para que pagina es valido, asi que podemos tirar de **Gobuster** o **Wfuzz** para encontrar otras rutas a las cuales poder atentar:
```
# wfuzz --hc=404 -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.10/FUZZ
```

Nos encuentra el siguiente directorio:
![[Pasted image 20230817203746.png]]

Si intentamos visitarlo, vemos que nos redirige al siguiente dominio:
![[Pasted image 20230817203800.png]]

Podemos contemplarlo en el **/etc/hosts** para poder visualizar la pagina. Nos estamos enfrentando a un **Moodle**, el cual, se usa en institutos educativos para gestionar algunos aspectos importantes como tareas, asistencias, etc...

Vemos que el inicio de la pagina, nos muestran una publicacion y debajo de ella, viene el nombre de un profesor:
![[Pasted image 20230817203837.png]]

Pues ya tenemos un nombre y una posible contraseña. Con **Crunch** vamos a crear un diccionario que nos ayudara a el proceso de fuerza bruta:
```
# crunch 15 15 -t Th4C00lTheacha^ > diccionario.txt
```

Ahora con **Wfuzz** podemos ejecutar un ataque de fuerza bruta contra el **Login**:
```
# wfuzz -c -t 100 -w Diccionario.txt -d 'anchor=&username=giovanni&password=FUZZ' http://teacher.htb/login/index.php
```

Y la contraseña seria la siguiente:
![[Pasted image 20230817204555.png]]

--------------
#### Moodle Exploitation - Code Injection (Abusing Math formulas in Quiz component) [RCE]  
Ahora que tenemos una cuenta de un profesor, podriamos proseguir. Lo que haremos acontinuación sera intentar ejecutar comandos de forma remota a través de un formulario de **Moodle**. Primero, iremos a algún curso disponible que nos pertenezca. Luego, nos iremos a los topicos y aqui, habilitaremos el modo edición:
![[Pasted image 20230817204746.png]]

Una vez creado, nos podemos apoyar de este [recurso](https://www.sonarsource.com/blog/moodle-remote-code-execution/) que nos explica bien como explotar este vulnerabilidad. A continuación, le daremos click a **+ Add an activity or resource**:
![[Pasted image 20230817204810.png]]

Luego, añadiremos un **Quiz**:
![[Pasted image 20230817204842.png]]

Añadiremos un nombre y una descripcion breve:
![[Pasted image 20230817204914.png]]

Luego damos click en **Save And Display**:
![[Pasted image 20230817204933.png]]

Nos rediccionara a nuestro **Quiz**, aqui, daremos click en **Edit Quiz**. Una vez aqui, daremos click en **+ a new question**:
![[Pasted image 20230817205009.png]]

Seleccionaremos **Calculated** y posteriormente a **Add**:
![[Pasted image 20230817205037.png]]

En esta sección, agregaremos un nombre y una descripción, si bajamos un poco más encontramos el apartado de **Answers** y es aqui donde ocurre la magia, vamos a colocar el payload de la pagina:
![[Pasted image 20230817205156.png]]

Le damos a **Save**, luego a **Next Page**. Nos redireccionara a otra pagina, desde aqui, podemos alterar la **URL** para poner un **0** y empezar a ejecutar comandos:
![[Pasted image 20230817205355.png]]

------------
#### Database Enumeration  
Dentro de la maquina, podemos intentar dar con el archivo de configuración de **Moodle** el cual suele tener credenciales para la base de dato:
```php
<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mariadb';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'root';
$CFG->dbpass    = 'Welkom1!';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => 3306,
  'dbsocket' => '',
  'dbcollation' => 'utf8mb4_unicode_ci',
);

$CFG->wwwroot   = 'http://teacher.htb/moodle';
$CFG->dataroot  = '/var/www/moodledata';
$CFG->admin     = 'admin';

$CFG->directorypermissions = 0777;

require_once(__DIR__ . '/lib/setup.php');

// There is no php closing tag in this file,
// it is intentional because it prevents trailing whitespace problems!
```

Con esta misma contraseña, vamos a conectarnos a la base de datos en busca de información interesante. En moodle, suele haber una tabla de nombre **mdl_user** la cual contiene usuarios y contraseñas hasheadas:
```
+-------------+--------------------------------------------------------------+
| username    | password                                                     |
+-------------+--------------------------------------------------------------+
| guest       | $2y$10$ywuE5gDlAlaCu9R0w7pKW.UCB0jUH6ZVKcitP3gMtUNrAebiGMOdO |
| admin       | $2y$10$7VPsdU9/9y2J4Mynlt6vM.a4coqHRXsNTOq/1aA6wCWTsF2wtrDO2 |
| giovanni    | $2y$10$38V6kI7LNudORa7lBAT0q.vsQsv4PemY7rf/M1Zkj/i1VqLO0FSYO |
| Giovannibak | 7a860966115182402ed06375cf0a22af                             |
+-------------+--------------------------------------------------------------+
```

-------------------
#### Cracking Hashes  
Hay una que parece esta en **MD5** (por la longitud de caracteres), si intentamos crackearla desde crackstations, vemos que la contraseña es la siguiente:
![[Pasted image 20230817210731.png]]

Esta contraseña nos deja autenticarnos como el usuario **Giovenni** en la maquina victima.

----------
#### Abusing Cron Job [Privilege Escalation]
Una vez como el usuario **GIovanni** podemos subir **PsPy** y empezar a enumerar procesos que se esten ejecutando en intervalos regulares de tiempo. Vemos uno muy interesante que nos podria permitir escalar comandos:
![[Pasted image 20230817210958.png]]

El archivo que se esta ejecutando, tiene el siguiente contenido:
```bash
#!/bin/bash
cd /home/giovanni/work;
tar -czvf tmp/backup_courses.tar.gz courses/*;
cd tmp;
tar -xf backup_courses.tar.gz;
chmod 777 * -R;
```

Basicamente esta metiendose a un directorio, esta creando un comprimido y posteriormente le asigna privilegios 777. Podemos aprovecharnos de esto creando un archivo y aplicando un enlace simbolico al propio archivo que de primeras no tenemos capacidad de escritura para poder modificarlo e inyectar codigo malicioso:
```
# ln -s -f /usr/bin/backup.sh test
```

Ahora, cuando root asigne los privilegios, podremos modificar el archivo:
![[Pasted image 20230817211346.png]]

Con esto, ya solo quedaria otorgarle **SUID** a la bash para escalar privilegios:
![[Pasted image 20230817211404.png]]




