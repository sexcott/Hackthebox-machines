-----------
- Tags: #radare2 #lfi #no-redirect #JWT #PHPSESSID #web-shell #sticky-notes #cyberchef  #sqli #qli-errorbased #AES #AES-Decrypt #linux
---------
## Técnicas utilizadas
- Local File Inclusion (LFI) [Abusing file_get_contents]  
- Abusing No Redirect  
- Forge PHPSESSID and getting valid Cookies  
- Forge JWT  
- Uploading WebShell  
- Obtaining system credentials through the webshell  
- Abusing Sticky Notes  
- Binary Analysis (Radare2)  
- SQL Injection (SQLI) [Error Based]  
- AES Decrypt (Cyberchef)
## Procedimiento
![[Pasted image 20230615133553.png]]

-------
#### Reconocimiento

El escaneo de nmap nos reporta lo siguientes puertos abiertos:
![[Pasted image 20230616115005.png]]
Si lanzo un whatweb sobra la web, podemos ver las tecnologias que corren por detras:

![[Pasted image 20230616115033.png]]

Si lanzamos un reconocimiento básico con **crackmapexec** sobre el **smb** podemos observar los nombres de dominio así como el nombre de la maquina:

![[Pasted image 20230616115111.png]]

Vemos el puerto **443** que pertenece al SSL/HTTPS, podemos conectarnos para que si hay algo interesante

-------------
#### Local File Inclusion (LFI) 

Vemos que en la pagina principal hay un buscador, en el, si intentamos un SQLI no funciona, si ponemos un espacio nos muestran todos los libros que hay en el inventario. Si le damos al botón de *block* que aparece en cada libro nos aparece un aviso de que la opción no esta disponible. Verificando el código fuente, específicamente el botón, vemos que hace una llamada a una función, si inspeccionamos los archivos *javascript* vemos uno que tiene de nombre *books*, de aquí se hace la llamada a los libros.

Hasta ahora, nada interesante, podemos tirar de **gobuster** o **wfuzz** para hacer directory fuzzing y encontrar algunos recursos ocultos. Dentro de los directorios encontrados, vemos un *portal*. Si accedemos a el nos encontramos con un login, que al intentar nuevamente inyecciones SQL no funciona, sin embargo, nos podemos registrar. Si nos registramos y logueamos vemos algunos apartados. Si verificamos las cookies, nos percatamos que estamos ante un **Json Web Token**.

Volviendo a la pagina principal, si intentamos a clickear en *book* y pasamos la petición por bupsuite, observamos que se hace una llamada a *book$(numero).html*. Si intentamos acontecer un **LFI** vemos que si es vulnerable. Podemos intentar atentar contra el */etc/hosts* pero como es windows, la ruta cambia, seria la siguiente:

	C:\Windows\System32\Drivers\etc\hosts

Podemos observar el */etc/hosts* de manera que se confirma el **LFI**. Ahora podríamos atentar contra los archivos **PHP** que se encuentren en el servidor. Si vamos por el archivo *bookscontroller.php* y formateamos la data correctamente, podemos ver el código en claro.

En el archivo *bookscontroller.php* vemos una ruta de configuración para una base de datos. Si intentamos atentar contra ella en el **LFI** vemos unas credenciales.

Si regresamos a la ruta de *portal* e intentamos fuzzear por directorios, encontramos que existe un *includes*. Si intentamos fuzzear también por archivos con extensión *.php*, podemos ver que hay uno de nombre **cookie**. Si intentamos observar su contenido a través del **LFI** podemos ver la manera en que se crea la cookie *PHPSESSID*

----------
#### Abusing No Redirect

Si intentamos entrar al apartado de *file management*, vemos que nos carga algo, pero no nos deja visualizarlo por que nos vuelve a redirigir a la pagina principal. Si interceptamos la petición con bupsuite y le pedimos que nos muestre la respuesta, podemos ver que hay data. Podemos cambiar el *302 Found* por un *200 OK* y podríamos ver la pagina en claro.
Nos encontramos ante un *uploader*, nos pide que solo subamos archivos *.zip*, si intentamos subir una *webshell* nos lanza un aviso que nos indica que esta opción es solo para administradores.

---------------
#### Forge PHPSESSID and getting valid Cookies  

Una vez teniendo la estructura básica para la creación de cookies podemos fácilmente tomar el código php, sustituir el usuario por el que deseemos. Basta con crear un ciclo que nos ejecuta el código unas cuantas veces para dar con la cookie correcta del usuario que deseemos. Sin embargo, no podríamos suplantar la sesión del usuario, dado que necesitamos aún el **Json Web Token**.

------------
#### Forge JWT

Para obtener el *secreto* del **Json Web Token** podemos intentar atentar contra la ruta de *fileController.php* que habíamos observado con anterioridad.  En el código, además de observar el *secreto*, también podemos ver la parte que nos impedía subir archivos sin tener los privilegios suficientes.

-------------
#### Uploading WebShell  

Una vez obtenido el **Json Web Token** y el **PHPSESSID** correspondiente de algún usuario administrador, podemos pasar al aparado que habíamos descubierto con anterioridad. Intentamos subir nuestra *webshell* y ahora si se nos permite, solo que se nos guarda automáticamente como *.zip*. Si intentamos capturar la petición con *burpsuite* y cambiamos el valor de *task* de *.zip* a *.php* vemos que se nos permite.

-------------
#### Obtaining system credentials through the webshell  

Si intentamos listar los recursos que se encuentran en la web, podemos ver algunas cosas que resultan de interés, si nos vamos a la carpeta de *PizzaDeliveryUserData* y tratamos de mostrar el contenido de todos los archivos, observamos que hay credenciales almacenadas.

-----------
#### Abusing Sticky Notes 

Con las credenciales obtenidas, podemos intentar validar si son validas a nivel de sistema con **crackmapexec**. Vemos que son validas para conectarnos al servidor **smb**, así que procedemos a listar el contenido que existe dentro de este recurso compartido.

Ahora, si intentamos conectarnos por **SSH** a la maquina victima con el usuario y contraseña que habíamos encontrado, vemos que se nos permite.  En nuestro escritorio, vemos un archivo *.html* que nos indica algo relacionado con las **Sticky notes**. Podemos intentar acceder a la ruta habitual donde se almacenan las notas, pero veremos que no hay nada, sin embargo, podemos intentar acceder a la ruta del backup de las notas. 
Encontramos varios archivos con extensión *.sqlite*, nos transferimos primero el archivo con más peso a la maquina de nosotros y lo inspeccionamos con **sqlite3**. Podemos encontrar la contraseña de otro usuario y así pivotar hacia el. 

----------
#### Binary Analysis (Radare2)  

Como este nuevo usuario, tenemos acceso a nuestro espacio personal. En nuestro escritorio, podemos ver un binario, lo que procederemos hacer es transferirnos este binario a nuestra maquina e inspeccionarlo con **Radare2**.

Analizar todas las funciones:

	radare2 > aaa 

Listar las funciones existentes

	radere2 > afl

Sincronizarlos con una función

	radare2 > s main

Para ver las instrucciones en bajo nivel que se ejecutar en ensamblador

	radare2 > pdf

Vemos en el binario que hay una petición a una pagina que esta corriendo por el puerto **1234**, si intentamos hacer un curl con los parámetros adecuados, vemos que nos retorna una key en AES Encrypt. Para estar mas cómodos, podemos hacer un **Port Fordwarding** de la pagina, para traérnosla a nuestro equipo local.

#### SQL Injection (SQLI) [Error Based]  

Vemos, que ademas de retornanos una clave AES, en los parámetros parece estar haciendo una **query** a la base de datos, si probamos colocando una comilla, vemos que nos regresa un error de sintaxis. Podemos aprovecharnos de esta inyección para dumpear información de la base de datos.

#### AES Decrypt (Cyberchief)

Una vez tengamos la credencial de usuario **Administrador**, podemos hacer uso de **CyberChef** para intentar desencriptar la contraseña.
Lo primero que tenemos que hacer es:

	-> From base64 = <password>
	-> AES Decrypt = <key> <iv-junk>

y obtenemos la contraseña del usuario **Administrador**

