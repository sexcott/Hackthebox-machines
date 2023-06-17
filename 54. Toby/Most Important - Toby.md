-----------
- Tags #gogs #php-malware-scanner #backdoor #socks5 #proxychains #api #wireshark #AES      #AES-Decrypt #PAM #linux #password-crack 
---------------

## Tecnicas utilizadas
- Abusing GOGS (Project Enumeration)  
- Static Code Analysis (Finding a backdoor with php-malware-scanner)  
- Code deofuscation  
- Reverse shell through backdoor  
- Setting up a SOCKS5 Proxy (Chisel/Proxychains)  
- Database Enumeration (Accessing GOGS)  
- Abusing API (Stealing an authentication hash in MYSQL through Wireshark)  
- Playing with epoch time to generate a potential list of passwords  
- Cracking Hashes  
- PIVOTING  
- Process Enumeration (pspy)  
- Abusing cron job to obtain a private key  
- Decrypting database passwords (AES Encryption)  
- Abusing PAM (Ghidra Analysis)  
- Getting the root password by abusing time  
- Advanced persistence techniques
-------------------
## Procedimiento

![[Pasted image 20230612193609.png]]

Comenzamos visitando la pagina principal y no cargan bien los recursos, eso es por que se esta haciendo Virtual hosting de la pagina principal.
Utilizamos el recurso de searchsploit para enumerar usuarios validos para el panel de autentificacion de wordpress, encontramos un usuario *Toby* que es valido.
Enumeracion de subdominios en busca de alguno valido. 
![[Pasted image 20230611164127.png]]

----------------------
#### Abusing GOGS (Project Enumeration)  

Encontramos un *backup*. Agregamos el subdominio al */etc/hosts* y posteriormente lo visitamos. La pagina es un *Gogs*:

	Gogs es un clon de la conocida plataforma GitHub, pero de Software Libre, publicado bajo licencia MIT. La mayor característica de Gogs es su ligereza, ya que puede ser desplegado mismo en una RasberryPi. Es un software muy sencillo de instalar, contando con versiones en Docker y Vagrant, se trata de una solución multiplataforma y muy intuitivo ya que su interfaz emula el funcionamiento y la estética de GitHub.

Encontramos un usuario en la pagina que no contiene repositorios visibles, si tratamos de fuzzear por repositiorios existente encontramos dos *backup* y *stars*. 
Clonamos el repositorio backup en nuestra maquina. En la carpeta encontramos una copia del sitio de wordpress, y como en todo los wordpress, encontramos credenciales para la base de datos en wp-config.php.

------------------------
#### Static Code Analysis (Finding a backdoor with php-malware-scanner)  

Probamos clonando el repositiorio de *scr34m/php-malware-scanner*  para buscar scripts maliciosos en el wordpress. El script detecta 4 archivos maliciosos dentro del repositorio.
Podemos ir buscando por malware en cada archivo detectado hasta encontrar el correcto.

-----------------
#### Code deofuscation

Encontramos una funcion eval que decodea un texto en base64, el problema esta que cuando lo decodea sigue siendo otra funcion eval. Asi que para no perder tanto tiempo, podemos automatizar el proceso con el siguiente script:
```bash
for i in $(seq 1 100); do
	sed -i 's/eval/<?php print/' wtf$i.php
	php wtf$i.php > wtf$(($i + 1)).php
done
```

---------------------
#### Reverse shell through backdoor  

Con el codigo desofuscado, intentamos que se vea mas legible para su interpretacion. Lo podemos hacer con algunas sustituciones dentro del archivo. Dandole un ojo al codigo, nos percatsmos que cuenta con la misma estructura que el apartado de comentario de wordpress. Si intentamos hacer que las condiciones se cumplan en el area de comentarios
nos percatamos que hay paquetes enviados a nuestra maquina(haciendo uso de wireshark). Vemos que la maquina victima esta intentando comunicarso con nosotros por el puerto *20053*. Si nos ponemos en escucha con *nc* y tramitamos la solicitud vemos que se nos manda un texto.
Si le aplicamos el proceso inverso con hexadecimal(`xxd -ps -r`) a la ultima cadena del texto, podemos ver un mensaje.
El mensaje nos da una key en XOR. Si volvemos a mandar la peticion por el repeter pero ahora que el valor despues de *:* sea *00* y pasamos a decodear en hexadecimal el *xor_key*, podemos ver que nos dan una key. ahora si hacemos un xor(en UTF8) con la key correspondiente tratando de ejecutar algun comando del sistema, y el resultado de la cadena lo pasamos a hexadecimal manteniendo la key del xor, podemos ver en texto claro el comando ejecutado a nivel de sistema. 

--------------
#### Setting up a SOCKS5 Proxy (Chisel/Proxychains)  

Intentando listar los puertos que estan corriendo en la maquina, nos percatamos que no hay manera de listarlos, ni con *netstat* ni con *ss*. Sacamos los puertos abiertos de */proc/net/tcp* y sacando sus respectivos valores de hexadecimal a decimal. Podemos intentar hacer un *dig*(ya que no existe ping en la maquina) al domino que habiamos encontrado en wp-config.php(mysql.toby.htb) para ver a que IP nos resuelve.
Lo siguiente hacer, es subir chisel a la maquina victima para traernos los puertos a los cuales la maquina tiene alcance.
Nos ponemos por un lado en modo server(nuestra maquina) y por otro en modo cliente(maquina victima). Tenemos que jugar con socks5 en la maquina cliente de la siguiente manera:

`./chisel client ip:puerto R:socks`

Posteriormente, abrimos el archivo */etc/proxychains* y establacemos un nuevo sock:

`socks5 127.0.0.1 <puerto-chisel>`

Si deseamos ver la web de manera mas clara, podemos declarar un nuevo proxy por foxyproxy en socks5 que pase por el proxy que acabamos de definir

----------------
#### Database Enumeration (Accessing GOGS)

Ahora que tenemos al alcance la maquina donde corre mysql, podemos intentar conectarnos a la base de datos con proxychain.
Podemos rompear la contraseña hasheadas que estan en la base de datos de wordpress para sacar la constraseña de toby.
La contraseña se reutiliza para entrar al portal de *Gogs* 

---------------
#### Abusing API (Stealing an authentication hash in MYSQL through Wireshark)

Enumerando el gogs, podemos ver que hay un repositorio de una pagina web. La pagina web tiene dos apis, una que genera contraseñas basadas en el tiempo actual y otra bastante rara que se conecta a determinada IP en base a un argumento que le pases por la URL. 
Si nos ponemos en escucha con *nc* por el puerto 3306, podemos ver que entra una peticion a nuestro mysql. Podemos habilitar mariadb y ponernos a interceptar el trafico con wireshark para ver las credenciales que se usan para autenticarse a nuestro host.
Lo primero que tenemos que hacer para que esto se acontesca(porque de primera no se puede, dado que no existe el usuario con el que se desea autenticar en nuestra base de datos) es:

Crear un usuario con el nombre solicitado -> `create user 'user'@'ip-victima' identified by 'password'`

Una vez hecho esto, intentamos denuevo la peticion y podemos ver la contraseña, pero esta esta encryptada y ademass contiene un salt. Lo que podemos hacer, es agarrar el el salt, y el hash e intentar crear nuestro propio hash de MYSQL para intentar romperlo.
Para armarlo, primero tendriamos que tomar el valor de los dos salt, lo tenemos que pasar a hexadecimal con cyberchef(to hex) y le quitamos los espacios en blanco, posteriormente, tenemos que tomar la contraseña y colocarla despues del *^*
El fomato a tener encuenta es el siguiente:

`$mysqlna$<salt-hexadecimal><salt-hexadecimal>*<password>`

#### Playing with epoch time to generate a potential list of passwords  

Viendo los comentarios del script, vemos que el ultimo "commit" fue en una fecha determinada, por lo tanto, podemos usar *epoch* para intentar generar una conteseña apartir de la fecha determinada, dado que en el script se esta haciendo alución a *time.time()*.
Podemos ir a la siguiente pagina: http://epochconverter.com e ir colocando los respectivos valores de la fecha del ultimo commit.
Nos da el tiempo correspondiente. Lo siguiente hacer es un script en python para generar algunas posibles contraseñas.

```python
import string, time

for i in range(epoch, epochmore):
	char = string.ascii_letters + string.digits
	random.seed(i)
	password = ''.join([random.choice(chars) for x in range(32)])
	print(password)
```

----------
#### Cracking Hashes 

Metemos las posibles contraseñas a un archivo para posteriormente intentar romper el hash que habiamos creado a partir de los salt y la contraseña con *john*. Y la obtenemos.

#### PIVOTING  

Podemos intentar conectarnos por SSH con la contraseña creackeada a alguna maquina otorgada por SOCK con el proxy que habiamos definido antes.

----------------
#### Process Enumeration (pspy)

Subimos el binario de pspy a la maquina para ver los comandos que se están ejecutando a intervalos regulares de tiempo e intentar abusar de algún proceso que este mal configurado.
El archivo lo podemos subir con *SCP* para facilitarnos la importacion del archivo. Una vez ejecutado, descubrimos una tarea que se ejecuta, esta mete la ID_RSA del usuario jack, a una carpeta en */tmp/* de manera temporal, esta id_rsa seguramente sea la necesaria para conectarnos a la maquina verdadera.

---------
#### Abusing cron job to obtain a private key  

Lo que podemos hacer, es hacer un bucle infinito, el cual intente leer por la key en alguna carpeta de */tmp/*, y que cuando el archivo no existe, no muestre nada. Se puede hacer de la siguiente manera:

```bash
while [ $? -ne 0 ]; do cat /tmp/*/key 2>/dev/null; done
```

Con esa id_rsa, podemos conectarnos a la maquina verdadera.

----------
#### Decrypting database passwords (AES Encryption)

En el *Gogs*, hizo falta analizar el siguiente repositorio, por lo que si vamos a ver que es, nos damos cuenta que es un *.db*
Si lo descargamos y le hacemos un *file* vemos que es un archivo de sqlite.
Podemos conectarnos a el con:

`sqlite3 .db`

Dentro de la base de datos, vemos que hay dos tablas. Unas coresponden a la KEY y al IV del encryptado AES.
La segunda tabla serian los datos encriptados. Asi que teniendo la KEY y el IV podemos desencriparlo con ciberchef.

------------
#### Abusing PAM (Ghidra Analysis)

En los archivos de sqlite3, encontramos un texto que nos indica que posiblemente se hayan modificado algunos archivos de autentificacion. Probablemente estos correspondan a los del recurso **pam.d** que vienen en UNIX. Si vistamos la carpeta anteriormente mencionada, y hacemos un `ls -la --full-time` podemos ver algunas cosas interesantes.
Los archivos que no tienen parte fraccional a nivel de tiempo, normalmente corresponde a instalaciones propias de paquetes del sistema, cuando si tienen esta parte fraccional, probablemente sea por que si esta manipulada.

Leyendo los archivos manipulados, encontramos que hay un archivo de autentificacion personalizado **mypam.so**.
Lo siguiente a realizar es pasarnos este archivo a nuestra maquina atacante para analizarnos con **Ghidra**. 


Analizando el archivo, podemos ver que se hace una comparativa de nuestra contraseña, con otra en un archivo del sistema, despues de esto, se hace un *unsleep(time)* para demorar un poco en la respuesta si el caracter es correcto.

-----------
#### Getting the root password by abusing time  
Podemos crear un diccionario con python de la siguiente manera:

`python3 -c 'import string; print("\n".join(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation))' > characters`

y creamos un script en bash que nos automatice la autentificacion:

```bash
#!/bin/bash

TIMEFORMAT=%E
Password=<first-latter-find>

for character in $(cat characters); do

	echo -n "$password$character: "
	time printf "%-10s" $password$character | su root 2>/dev/null
	
done
```















