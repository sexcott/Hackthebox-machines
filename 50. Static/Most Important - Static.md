----------
- Tags: #fixgz #totp #static-routes #xdebug #php-fpm #capabilities #path-hijacking
----------
## Tecnicas utilizadas

- Compressed File Recomposition (Fixgz)  
- Abusing TOTP (Python Scripting - NTP protocol)  
- Playing with Static Routes  
- XDebug Exploitation (RCE)  
- Abusing PHP-FPM (RCE) [CVE-2019-11043] (PIVOTING)  
- Abusing Capabilities (cap_setuid + Path Hijacking | Privilege Escalation)

## Procedimiento

![[Pasted image 20230608112557.png]]


Nmap nos identifica que la pagina principal de la web contiene un *robots.txt*, de ahi saca que existen dos rutas:

![[Pasted image 20230610094229.png]]


#### Compressed File Recomposition (Fixgz)

Visitando la primera ruta encontada, vemos que hay un *login*, intentando con credenciales comunes, nos damos cuenta que *admin:admin* es valida, solo que tiene como seguridad un segundo factor de autentificación.
Analizando la siguiente ruta, nos encontramos con que tenemos capacidad de *Directory Listing*, ademas podemos ver que existen dos archivos.
Hay un *.sql.tar* que esta corrupto, si intemtamos descomprimirlo no vamos a poder dado a que esta dañado. Si listamos el contenido del comprimido con *7z* vemos que adentro hay una base de datos. Podemos recomponer el archivo con una heramienta que se llama *FixGz*. 

---------------

#### Abusing TOTP (Python Scripting - NTP protocol)  

Dentro del archivo, vemos la credenciales del usuario, ademas del **TOTP** (*El algoritmo de contraseña de un solo uso o TOTP es un algoritmo que permite generar una contraseña de un solo uso que utiliza la hora actual como fuente de singularidad*). Como la clave de doble autentificacion es basada en tiempo, y dado que quizás la fecha y el tiempo de la maquina victima no sean los mismos, vamos a enumerar por UDP en busca de NTP, para poder sincronizarnos con la maquina. Podemos usar *pyotp* y *ntplib*. Ahora, con python interactivo, hacemos lo siguiente:

```python
import pyotp
import ntplib
from time import ctime

# Definimimos un cliente
client = ntplib.NTPClient()

# Declaramos el cliente al que deseamos conectarnos
response = client.request("<Victim>")

	# Colaboramos que estamos conectados
#response

	# Saca la hora y fecha actual del equipo, el response.tx_time viene como un hash por defecto.
#ctime(response.tx_time)

# el valor del totpz
totp = pyotp.TOPT("<opt>")	

# Printea el token
print("El TOKEN es -> %s" % totp.at(response.tx_time))
```

---------------

#### Playing with Static Routes 

Una vez habiendo ingresado el *TOTP* correcto, nos redirecciona a un dashboard donde podemos apreciar varias *IP's* junto con un input. Si colocamos el nombre de cualquier cosa, nos descarga una VPN.

Nos conectamos con ella con *OpenVPN*, no sin antes colocar los subdominios indicados en el archivo *.vpn*. 
Agregamos las rutas estaticas para tener alcance con ellas con el siguiente comando:

`ip route add <ip>/24 dev tun9` 

Podemos listar las ips a las que tenemos alcance con:

`ip route list`

-------------------------------

#### XDebug Exploitation (RCE)  

Una vez agradas las rutas, tenemos conectividad. Visitamos la pagina web y vemos que es el mismo login que ya habiamos encontrado, esto, por que se esta aplicando port fortwarding. Si vemos la raiz, vemos que hay un nuevo archivo *Info.php*  el cual nos dice que el modulo **Xdebug** esta activado.

	Xdebug es una extensión de PHP que proporciona la capacidad de depuración código y errores.​ Utiliza DBGp que es protocolo de depuración simple que se usa para comunicar el motor de depuración propio de php con un cliente, normalmente un IDE. Xdebug también esta disponible para PECL.​

Xdebug sufre de una vulnerabilidad de tipo RCE, si buscamos por un exploit en google salen demasiados, puedemos coger uno y aprovecharnos de esta vulnerabilidad.

-------------

#### Abusing PHP-FPM (RCE) [CVE-2019-11043] (PIVOTING)  

Hacemos local port fortwarding de el nuevo host que esta en nuestro segmento de red para trernos el puerto 80 a nuestra maquina y ver el contenido de la web con mas comidad.
Viendo las cabeceras de la web, vemos que cuenta con una version de *PHP-FPM* vulnerable. Si buscamos por un exploit en google encontramos demasiados.

Encontramos uno y lo explotamos. Metemos el *Netcat* a la maquina para entablarnos una reverse shell desde esta, por que la nueva maquina no tiene conectividad con la nuestra.

----------------------

#### Abusing Capabilities (cap_setuid + Path Hijacking | Privilege Escalation)

Si listamos por las capibilities en la nueva maquina comprometida, podemos observar que existe una en un binario.
Podemos secuestrar el comando **OpenSSL** para ejecutar un comando que queramos, ya que el binario tiene la capacidad de ejecutar esta herramienta al momento de crear una VPN







