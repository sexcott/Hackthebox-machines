---------
- Tags: #information-leakage #wordpress #draft-posts #rocket-chat-bot #polkit
----------
## Ténicas utilizadas
- Information Leakage  
- Abussing WordPress - Unauthenticated View Private/Draft Posts  
- Abusing Rocket Chat Bot  
- Polkit (CVE-2021-3560) [Privilege Escalation]
## Procedimiento
![[Pasted image 20230807194126.png]]
#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina victima podemos ver los siguientes puertos activos:
```ruby
# nmap -sCV -p22,80,443 -oN Ports 10.10.11.143
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-07 20:52 UTC
Stats: 0:00:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 95.83% done; ETC: 20:52 (0:00:00 remaining)
Nmap scan report for 10.10.11.143
Host is up (0.13s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 1005ea5056a600cb1c9c93df5f83e064 (RSA)
|   256 588c821cc6632a83875c2f2b4f4dc379 (ECDSA)
|_  256 3178afd13bc42e9d604eeb5d03eca022 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Potentially risky methods: TRACE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.65 seconds
```

Un escaneo con **whatweb** sobre las tecnologías web nos muestra el siguiente resultado:
```ruby
# whatweb 10.10.11.143
http://10.10.11.143 [403 Forbidden] Apache[2.4.37][mod_fcgid/2.3.9], Country[RESERVED][ZZ], Email[webmaster@example.com], HTML5, HTTPServer[CentOS][Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9], IP[10.10.11.143], MetaGenerator[HTML Tidy for HTML5 for Linux version 5.7.28], OpenSSL[1.1.1k], PoweredBy[CentOS], Title[HTTP Server Test Page powered by CentOS], UncommonHeaders[x-backend-server], X-Backend[office.paper]
```


#### Information Leakage  
Al visitar la pagina, no encontramos nada relevante. Fuzzeando por directorios y archivos no se llega a completamente nada, sin embargo, al hacerle un **curl** y mirar las cabeceras vemos que se leakea un subdominio:
```ruby
# curl -s -X GET http://10.10.11.143 -I
HTTP/1.1 403 Forbidden
Date: Mon, 07 Aug 2023 23:41:02 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8
```

Si lo colocamos en el **/etc/hosts** y visitamos la pagina, encontramos un **Wordpress.**

-----------
#### Abussing WordPress - Unauthenticated View Private/Draft Posts  
Si lanzamos un **wpscan** podemos ver que tiene cierta vulnerabilidad peculiar que nos permite leer cosas privadas del usuario:
![[Pasted image 20230809040454.png]]

Basicamente, nos dique que al colocar esta url: `http://office.paper/?static=1&order=` si filtran las notas, si visitamos dicha pagina. podemos ver lo sigueinte:
![[Pasted image 20230809040544.png]]

Un nuevo subdominio valido.

-----------
#### Abusing Rocket Chat Bot 
Si visitamos el nuevo subdominio, encontramos que es un tipo de chat grupal:
![[Pasted image 20230809184354.png]]

Hay un bot que, nos indica que nos puede leer archivos de la carpeta **/sales/** además nos dice que podemos listar:
![[Pasted image 20230809184709.png]]

Ademas podemos leer archivos:

![[Pasted image 20230809184744.png]]

Leyendo un poco más, podemos encontrar unas credenciales en un archivo de variables de entorno:
![[Pasted image 20230809184821.png]]

Estas, nos sirve para conectarnos con **SSH** con el usuario **dwight**.

-------------
#### Polkit (CVE-2021-3560) [Privilege Escalation]
Una vez dentro, si listamos los procesos con `ps -faux` vemos que hay un proceso de **Poolkit**:
![[Pasted image 20230809190440.png]]

Si buscamos en google por maneras de escalar privilegios con esto, encontramos este [articulo](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) que nos explica como escalar, simplemente tenemos que ejecutar el siguiente comando:
```
# ./script.sh -u=user -p=user
```

Ahora, nos contectamos como este usuario, hacemos un `bash -p` y ya estariamos como root:
![[Pasted image 20230809190914.png]]

