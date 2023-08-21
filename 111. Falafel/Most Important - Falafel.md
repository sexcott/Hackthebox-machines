--------
- Tags:
---------
## Técnicas utilizadas
- Information Leakage  
- SQL Injection (SQLI) - Abusing substring function  
- Obaining user passwords [Python Scripting]  
- PHP Type Juggling Exploitation (0e hash collision)  
- Abusing File Upload - File name truncation (Bordering the limits)  
- Abusing video group - Taking a screenshot to view a password [GIMP && Playing with virtual_size]  
- Abusing disk group to read the flag [debugfs] [Privilege Escalation]
## Procedimiento
![[Pasted image 20230817211747.png]]
#### Reconocimiento
Un escaneo con **nmap** nos muestra los siguientes puertos abiertos, con sus respectivos servicios y versiones:
```ruby
# nmap
```

Con **whatweb** podemos listar las tecnologías que estan corriendo por detrás del sitio web:
```ruby
# whatweb
```

---------------------
#### Information Leakage  
El escaneo de **nmap** nos reporta que hay un **robots.txt** el cual, al visitarlo, hace alución a que probablemente existan archivos **.txt** ya que referencia una **wildcard** acompañado de la extension antes mencionada:
```
Image Robots.txt
```

Visitando la web, nos encontramos un mensaje de bienvenida que nos da una pequeña descripción de lo que es el sitio web:
```
Image Welcome message
```

En la esquina superior derecha, vemos un enlace que nos redirecciona a **Login**. A la par, podemos ir **Fuzzeando** por archivos con extensiones **.txt** dado que el **Robots.txt** nos dio esa pista:
```
# wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.10/FUZZ.txt
```

y encontramos lo siguiente:
```
Image Wfuzz Output
```

Dentro, nos dicen que pudieron acceder a la cuenta de **Admin** sin proporcionar contraseña, lo cual, de primeras nos hace pensar en un **Bypassing**. Además, nos revelan otro usuario a nivel de web de nombre **Chris'**.

--------------
#### SQL Injection (SQLI) - Abusing substring function  
Jugando un rato con el **Login** vemos que es vunlerable a **SQLi** y podemos guiarnos de la respuesta del servidor para ir enumerando la base de datos. Cuando acertamos con el numero correcto de columnas, vemos que se nos muestra un mensaje que dice que las credenciales de **admin** son incorrectas:
```
IMage Server Response
```

Pero, al intentar usar un **union select**  para ir mostrando nuestro input en el output, vemos que nos lanza un aviso de intento de hackeo:
```
Image hacking attempt
```

