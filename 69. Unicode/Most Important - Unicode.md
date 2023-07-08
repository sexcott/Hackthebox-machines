----------
- Tags: #JWT #JWKS #mkjwk #open-redirect #lfi #pyinstxtractor #pycdc 
-------
## Técnicas utilizadas
- JWT Enumeration  
- JWT - Claim Misuse Vulnerability  
- JSON Web Key Generator (Playing with mkjwk)  
- Forge JWT  
- Open Redirect Vulnerability  
- Creating a JWT for the admin user  
- LFI (Local File Inclusion) - Unicode Normalization Vulnerability  
- Abusing Sudoers Privilege  
- Playing with pyinstxtractor and pycdc  
- Bypassing badchars and creating a new passwd archive (Privilege Escalation)
## Procedimiento
![[Pasted image 20230625234535.png]]

----------
#### Reconocimiento
Si lanzamos un escaneo con **nmap** podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80 10.10.11.126 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-26 10:41 MST
Nmap scan report for 10.10.11.126
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fda0f7939ed3ccbdc23c7f923570d777 (RSA)
|   256 8bb6982dfa00e5e29c8faf0f449903b1 (ECDSA)
|_  256 c989273e91cb51276f3989361041df7c (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 503
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.00 seconds
```
Con **WhatWeb** podemos ver las siguientes tecnoligías corriendo por detrás del sitio web:
```ruby
# whatweb 10.10.11.126
http://10.10.11.126 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.126], Meta-Author[Mark Otto, Jacob Thornton, and Bootstrap contributors], MetaGenerator[Hugo 0.83.1], Title[Hackmedia], nginx[1.18.0]
```
La pagina web no parece tener nada interesante, podemos encontrar una sección para iniciar sesión y otra para registrarnos. Si nos registramos, podemos ver el dashboard de la pagina.
En la pagina vemos una parte para poder comprar algo, otra para subir archivos y por ultimos para deslogearnos.

--------
#### JWT Enumeration 
##### JWT - Claim Misuse Vulnerability
Enumerando nuestras posibles cookies, nos encontramos con que tienen la estructura de **JWT** ( Json Web Token ). Si vamos a **jwt.io** podemos enumerar un poco la estructura de nuestro **JWT**. Vemos que en la estructura se define un campo **jku**, este hace referencia a un archivo de nombre **jwks.json** que según google son:

	El conjunto de claves web JSON (WKS) es un conjunto de claves que contiene las claves públicas que deben utilizarse para verificar cualquier señal web JSON (JWT) emitida por un servidor de autorización y firmada utilizando los algoritmos RSA o ECDSA.

Bueno, pues para crear un nuevo **JWT** vamos a tener que disponer de una clave **publica** y una **privada**. 

--------
#### JSON Web Key Generator (Playing with mkjwk)  
##### Forge JWT
Existe una herramienta web que nos puede ayudar a generar cada una de estas, esta se llama [mkjwk](https://mkjwk.org/). Para generarla, tenemos que ir adecuando la información que se encuentra en el **jwks.json** de la pagina. Esto nos generara una **Public Key** y una **Private Key** que podremos utiilizar para crear un nuevo **JWT**. Cabe mencionar que tenemos que abrir un servidor y alojar nuestro **jwks** con el respectivo valor de **n** modificado, ya que tenemos que espeficiarselo en el **jku**. Sin embargo, podremos ver que la validacion falla.

##### Open Redirect Vulnerability
Esto puede estar sucediendo porque quizás el **JWT** tiene alguna medida de seguridad para que el campo **jku** solo pueda recibir como parametro la pagina host. Podemos intentar aprovecharnos de un **Open Redirect** que la pagina principal tiene para apuntar hacia nuestra maquina y que asi interprete nuestro **jwks**.

----------
#### LFI (Local File Inclusion) - Unicode Normalization Vulnerability
Podemos encontrar una vulnerabilidad de tipo **Local File Inclusion** en uno de los apartados encontrados en el dashboard. Si intentamos listar el **passwd** de la maquina, vemos que no funciona e incluso nos dejan un mensaje diciendonos que jamás podremos burlar sus filtros:
```
images
```

Pues bien, intentando algunos de los bypassings tipicos, vemos que no funcionan. Pero si intentamos representar la barra en formato **unicode** ( como el nombre de la maquina, casualmente ) vemos que si nos permite listar el contenido:
```
image
```

Si intentos atentar contra el archivo de configuración de **NGINX** podremos ver que se nos habla de un archivo **db.yaml** que probablemente contenga contraseñas:
```
image
```

--------------
#### Abusing Sudoers Privilege

Si hacemos un *sudo -l* podemos ver que contamos con el privilegio de ejecutar */usr/bin/treport* el cual sirve para generar reportes.
Sin embargo, si intentamos generar algún tipo de error en la aplicación, podemos ver que nos muestra el tipico error de una app en **python**:
```
image
```

--------
#### Playing with pyinstxtractor and pycdc 

Vamos a transferirnos el archivo a nuestra maquina para examinarlo con herramientas como [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) ( nos permite extraer el contenido de un archivo ejecutable generado por **pyinstaller** ) y [pycdc](https://github.com/zrax/pycdc) ( pretende traducir el código de bytes de Python compilado en código fuente de Python válido y legible por humanos ).

El codigo resultante seria el siguiente:
```python
```

--------------
#### Bypassing badchars and creating a new passwd archive (Privilege Escalation)

En el codigo, podemos ver una parte que no esta sanitizada y que podriamos utilizar para colar algunos parametros extras contemplando la lista negra de palabras:
```python

```

Podriamos alterar el */etc/passwd* para cambiar la contraseña de root, hacer un curl a nuestra IP y depositar el nuevo **passwd** en el */etc/passwd* de la maquina victima.


