------------
- Tags: #subdomain #fuzzing #gophish #regeorg #winrm #cron-job #impersonating #bypassing-firewall
------------
## Tecnicas utilizadas
- Subdomain Enumeration  
- Information Leakage  
- Password Fuzzing  
- Gophish Template Log Poisoning (Limited RCE)  
- Internal Port Discovery  
- reGeorg - Accessing internal ports through a SOCKS proxy (proxychains)  
- Accessing the WinRM service through reGeorg and SOCKS proxy  
- Abusing Cron Job + SeImpersonatePrivilege Alternative Exploitation  
- Playing with PIPES - pipeserverimpersonate  
- Impersonating users and executing commands as the impersonated user  
- Bypassing Firewall Rules (BlockInbound/BlockOutbound)  
- Abusing Services  
- Alternate Data Streams (ADS)
----------------
## Procedimiento
![[Pasted image 20230603191429.png]]
- Usamos herramientas de estenografía para ver si hay informacion relevante en la imagen del burro que se encuentra en la pagina principal de la pagina.
- Fuzzing de subdominios y encontramos uno con nombrre `admin`. Dentro de este subdominio tambien se Fuzzea y se haya un .js con informacion relevante. La informacion que encontramos esta en ROT13, usamos algun decodificador en linea para aplicar el proceso inverso. Colocamos el codigo en cualquier consola de navegador para debugearlo. Miramos el valor de las variables simplemente pasando su identificador a la consola y esta misma nos da el valor.
- Las variables tienen el valor de palabras, las cuales al juntarlas no dan un mensaje. Nos brindan un path de un recurso de red, nos da los parametros y nos dan los valores. Probando con el action `list` nos dice que la key no es correcta -> `Key wrong`. Empleamos un ataque de fuerza bruta con wfuzz para fuzzar por la posible contraseña. Con la key correspondiente, si hacemos un list a la pagina `HackTheBox` nos regresa un hash con una extension `.log`. 
- Enumeramos la siguiente pagina en el puerto 64831 y es un gophish, tiene credenciales por defecto: `admin:gophish`.  Encontramos plantillas que corresponden con los sitios que nos mostraban las variables. Nos hace pensar que se estaban montando campañas de phishing para los sitios colocados ahi. Echandole un ojo a las plantillas, vemos un dominio `www.hackthebox.htb` que nos resuelve a una pagina. Cada que colocamos alguna credencial, se nos crea un nuevo log en el recurso que habiamos encontrado en la otra pagina, probablemente sean los datos que estamos ingresando y se guardan en forma de log. Al listar la credencial con la cookie correcta(se nos asigna automaticamente cuando ingresamos al sitio web malicioso) podemos ver el registro de los datos ingresados. Intentanto inyectar codigo PHP, vemos que si lo interpreta. con el parametro encontrado `show` y la credencial encontrada, intentamos mostra el log con nuestra cookie. Y como podemos observar no tenemos habilitada la ejecucion remota de comandos, sin embargo podemos usar la funcion `print_r(scandir('.'))` para listar los recursos del directorio actual de trabajo. Podemos usar `file_get_contents()` para leer archivos residentes en el servidor. Leemos el archivo `web.config.old` y vemos que hay credenciales.
- Fuzzemos el otro servicio web expuesto en el puerto `6666`. Listamos puertos locales en la maquina victima gracias a que en el servicio expusto hay ciertos comandos que se nos permiten ejecutar, entre ellos esta el `netstat`. Podemos aplicar un filtrado para ver mas comodo los datos como el siguiente:
  `grep "\"local port\"" | tr -d '"' | tr -d ',' | sed 's/^ *//' | sort -k 2 -nu`.
  Encontramos el puerto `5985` de `WinRm`. Buscamos por el recurso en la red de `reGeorge`.  De todos los archivos, el que nos interesa es el tunnel.aspx. Pasamos a base64 todo el archivo e intentamos subirlo a la pagina web con `file_put_contents("nombredearchivo", base64_decode($contenido_base_64")`. Una vez arriba el archivo, tenemos que visualizarlo con show para intepretarlo. Una vez creada la pagina de tunnel.aspx, nos clonamos el repositorio completo de `reGeroge`.
  Ejecutamos el script en python2, apuntando el recurso malicioso que hemos podido lograr subir y proporcionamos un puerto. Posteriormente tenemos que jugar con proxychain para configurar un proxy `/etc/proxychains.conf`, este nos lo brinda el script en python de `reGeorge` `socks4 127.0.0.1 1234` probamos las credenciales encontradas en `web.config.log` con evil-winrm, sin olvidar utilizar el comando `proxychain` al principio y atentando a nuestra propia ip ya que `tunnel.aspx` nos tunneliza el puerto a nuestra maquina por proxychain.
- Inspeccionamos la carpeta `util` encontrada en la raiz del sistema, dentro de ella hay un directorio oculto llamado `scripts`, en su interior hay varios scripts.
- Lo que procede a continuacion es robarnos el LogFile, como tenemos permiso de escritura en el archivo `clean.ini`(lo sabemos porque si usamos `net user simple` nos damos cuenta que pertenecemos a `project-managers` que listando los permisos del archivo con `icacls clean.ini` este grupo tiene permiso de escritura sobre este archivo.) procederemos a robarnos la ruta:
    `echo [Main] > clean.ini`
    `echo LifeTime=100 >> clean.ini`
    `echo LogFile=C:\util\scripts\sexcott.txt >> clean.ini`
    `echo Directory=c:\inetpub\logs\logfiles >> clean.ini`
	Lo proximo hacer, es clonarnos la herramienta de `decoder-it` mas especificamente `pipeserverimpersonate.ps1`. Hacemos uso del recurso `AppLockerBypasses` de github para ver donde podemos subir el archivo y que no haya problemas al ejecutarlo.
	Lo subimos facilmente gracias a evil-winrm con `upload /path/to/upload`.
	Ahora lo que haremos es crear un nuevo `clean.ini` pero que apunte al pipe del `impersonate.ps1` que subimos a la maquina, pero tenemos que cambiar un poco el LogFile de la siguiente manera:
	`echo LogFile=\\.\pipe\dummypipe >> clean.ini`
  Ejecutamos el `impersonate.ps1` haciendo alución a la ruta donde lo subimos.
  Subimos el `netcat` y un archivo `.bat` que va a contener lo siguiente `C:\ruta\de\nc.exe -lvp 4444 -e cmd.exe`.
  Modificamos el archivo impersonate desde nuestra maquina local para definir el comando que queramos que ejecute el usuario a impersonar a la hora de que apunte al pipe el LogFile, asi que añadiremos la siguiente linea al script:
  `Copy C:\Windows\System32\spool\drivers\color\sexcott.bat C:\util\scripts\spool\sexcott.bat`.
  Subimos el nuevo impersonate.ps1 y lo ejecutamos. Una vez se ejecute el pipe, desde nuestra maquina nos contectamos a nuestra propia IP por el puerto que hayamos definido en el `.bat` utilizando proxychain como comando inicial.
- Ahora, una vez dentro del sistema como el usuario `Hacker`, seguiremos enumerando el servicio que nos brindaba el puerto 6666, anteriormente vimos `netstat`, ahora probaremos con `services` para listar los servicios internos del sistema. Filtramos por el nombre del servicio para que nos sea mas como. Nos interesa especificamente el servicio de `UserLogger`. Para enumerar el servicio podemos usar:
  `reg query HKLM\System\CurrentControlSet\Services\userlogger`
  Lo que haremos a continuacion, sera ver si tenemos el control de parar e iniciar el servicio con el siguiente comando:
  `sc stop userlogger` -> Apagar
  `sc start userlogger` -> Iniciar
  Podemos internat encender el servicio con parametros adicionales, intentamos depositar el log en la raiz del sistema como ejemplo:
  `sc start userlogger C:\user.txt;`
  Vemos que si podemos dos puntos, el archivo no nos concatena el `.log`.
  Esto lo aprovecharemos para darle permisos FULL a la flag de root de la siguiente manera
  `sc start userlogger C:\Users\Administrator\Desktop\root.txt:`
  Al final tenemos que ver ver el `alternative data string` del `root.txt` con dir /r /s para ver, pero como no tenemos permisos de lectura no lo sabremos, asi que con `more` podemos fuzzear por la ADS como por ejemplo `:flag.txt`.
  Al final sacamos el valor de la flag de la siguiente manera:
  `more < C:\Users\Administrator\Desktop\root.txt:flag.txt`
  
  
  
  
  