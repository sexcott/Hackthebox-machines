------
- Tags: #svn #information-leakage #vhost #azure #azure-devops #IIS #Yaml 
- ----------
## Técnicas utilizadas
- SVN - Subversion Enumeration  
- Information Leakage  
- VHost Fuzzing - Gobuster  
- Azure DevOps Enumeration  
- Abusing Azure DevOps - Creating a Branch  
- Abusing Azure DevOps - Playing with existing Pipelines [RCE]  
- IIS Exploitation  
- Elevating our Azure DevOps privilege  
- Abusing Azure DevOps - Creating a new Pipeline  
- Azure DevOps Exploitation - Creating a malicious YAML file [Privilege Escalation]
## Procedimiento

![[Pasted image 20230828202107.png]]

#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos ver los siguientes puertos abiertos con sus respectivos servicios y versiones:
```ruby
# nmap -sCV -p80,3690,5985 -oN Ports 10.10.10.203
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-28 20:20 PDT
Nmap scan report for 10.10.10.203
Host is up (0.26s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.80 seconds
```

Un escaneo con **WhatWeb** nos muestra las siguientes tecnologías corriendo por detrás del sitio web:
```ruby
# whatweb 10.10.10.203
http://10.10.10.203 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.203], Microsoft-IIS[10.0], Title[IIS Windows Server], X-Powered-By[ASP.NET]
```

#### SVN - Subversion Enumeration  
Vemos que el puerto **3690** esta abierto, este suele pertenecer a un aplicacion de nombre **SVN** que según google, es una aplicacion para control de versiónes asi como lo seria **Git**. Bueno, apoyandonos de [hacktricks](https://book.hacktricks.xyz/v/es/network-services-pentesting/3690-pentesting-subversion-svn-server) podemos empezar a enumerar el servicio. Lo primero seria ver el banner del servicio, esto lo podemos hacer tanto con **NetCat** como con **TelNet**:
```
# nc -vn 10.10.10.10 3690
(UNKNOWN) [10.10.10.203] 3690 (svn) open
( success ( 2 2 ( ) ( edit-pipeline svndiff1 accepts-svndiff2 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay inherited-props ephemeral-txnprops file-revs-reverse list ) ) ) 
```

Ahora, podemos intentar listar los posibles proyectos con el siguiente comando:
```ruby
# svn ls svn://10.10.10.203
dimension.worker.htb/
moved.txt
```

Vemos que hay dos archivos disponibles. Ahora, podemos ver los commit de estos con el siguiente comando:
```python
# svn log svn://10.10.10.203
------------------------------------------------------------------------
r5 | nathen | 2020-06-20 06:52:00 -0700 (sáb 20 de jun de 2020) | 1 línea

Added note that repo has been migrated
------------------------------------------------------------------------
r4 | nathen | 2020-06-20 06:50:20 -0700 (sáb 20 de jun de 2020) | 1 línea

Moving this repo to our new devops server which will handle the deployment for us
------------------------------------------------------------------------
r3 | nathen | 2020-06-20 06:46:19 -0700 (sáb 20 de jun de 2020) | 1 línea

-
------------------------------------------------------------------------
r2 | nathen | 2020-06-20 06:45:16 -0700 (sáb 20 de jun de 2020) | 1 línea

Added deployment script
------------------------------------------------------------------------
r1 | nathen | 2020-06-20 06:43:43 -0700 (sáb 20 de jun de 2020) | 1 línea

First version
------------------------------------------------------------------------
```

Podemos intentar descargar estos de la siguiente manera:
```
# svn checkout svn://10.10.10.203
A    dimension.worker.htb
A    dimension.worker.htb/LICENSE.txt
A    dimension.worker.htb/README.txt
A    dimension.worker.htb/assets
A    dimension.worker.htb/assets/css
A    dimension.worker.htb/assets/css/fontawesome-all.min.css
A    dimension.worker.htb/assets/css/main.css
A    dimension.worker.htb/assets/css/noscript.css
A    dimension.worker.htb/assets/js
A    dimension.worker.htb/assets/js/breakpoints.min.js
A    dimension.worker.htb/assets/js/browser.min.js
A    dimension.worker.htb/assets/js/jquery.min.js
A    dimension.worker.htb/assets/js/main.js
A    dimension.worker.htb/assets/js/util.js
A    dimension.worker.htb/assets/sass
A    dimension.worker.htb/assets/sass/base
A    dimension.worker.htb/assets/sass/base/_page.scss
A    dimension.worker.htb/assets/sass/base/_reset.scss
A    dimension.worker.htb/assets/sass/base/_typography.scss
A    dimension.worker.htb/assets/sass/components
A    dimension.worker.htb/assets/sass/components/_actions.scss
A    dimension.worker.htb/assets/sass/components/_box.scss
A    dimension.worker.htb/assets/sass/components/_button.scss
A    dimension.worker.htb/assets/sass/components/_form.scss
A    dimension.worker.htb/assets/sass/components/_icon.scss
A    dimension.worker.htb/assets/sass/components/_icons.scss
A    dimension.worker.htb/assets/sass/components/_image.scss
A    dimension.worker.htb/assets/sass/components/_list.scss
A    dimension.worker.htb/assets/sass/components/_table.scss
A    dimension.worker.htb/assets/sass/layout
A    dimension.worker.htb/assets/sass/layout/_bg.scss
A    dimension.worker.htb/assets/sass/layout/_footer.scss
A    dimension.worker.htb/assets/sass/layout/_header.scss
A    dimension.worker.htb/assets/sass/layout/_main.scss
A    dimension.worker.htb/assets/sass/layout/_wrapper.scss
A    dimension.worker.htb/assets/sass/libs
A    dimension.worker.htb/assets/sass/libs/_breakpoints.scss
A    dimension.worker.htb/assets/sass/libs/_functions.scss
A    dimension.worker.htb/assets/sass/libs/_mixins.scss
A    dimension.worker.htb/assets/sass/libs/_vars.scss
A    dimension.worker.htb/assets/sass/libs/_vendor.scss
A    dimension.worker.htb/assets/sass/main.scss
A    dimension.worker.htb/assets/sass/noscript.scss
A    dimension.worker.htb/assets/webfonts
A    dimension.worker.htb/assets/webfonts/fa-brands-400.eot
A    dimension.worker.htb/assets/webfonts/fa-brands-400.svg
A    dimension.worker.htb/assets/webfonts/fa-brands-400.ttf
A    dimension.worker.htb/assets/webfonts/fa-brands-400.woff
A    dimension.worker.htb/assets/webfonts/fa-brands-400.woff2
A    dimension.worker.htb/assets/webfonts/fa-regular-400.eot
A    dimension.worker.htb/assets/webfonts/fa-regular-400.svg
A    dimension.worker.htb/assets/webfonts/fa-regular-400.ttf
A    dimension.worker.htb/assets/webfonts/fa-regular-400.woff
A    dimension.worker.htb/assets/webfonts/fa-regular-400.woff2
A    dimension.worker.htb/assets/webfonts/fa-solid-900.eot
A    dimension.worker.htb/assets/webfonts/fa-solid-900.svg
A    dimension.worker.htb/assets/webfonts/fa-solid-900.ttf
A    dimension.worker.htb/assets/webfonts/fa-solid-900.woff
A    dimension.worker.htb/assets/webfonts/fa-solid-900.woff2
A    dimension.worker.htb/images
A    dimension.worker.htb/images/bg.jpg
A    dimension.worker.htb/images/overlay.png
A    dimension.worker.htb/images/pic01.jpg
A    dimension.worker.htb/images/pic02.jpg
A    dimension.worker.htb/images/pic03.jpg
A    dimension.worker.htb/index.html
A    moved.txt
Revisión obtenida: 5
```

Esto nos creara los respectivos directorios, asi como descargar los archivos individuales en la carpeta actualmente en uso:
![[Pasted image 20230830202322.png]]

El archivo **Moved.txt** tiene el siguiente contenido:
```
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)
```

Este nos indica que el repositorio ha migrado y que ahora podemos encontrar la versión más reciente en `http://devops.worker.htb` asi que podemos contemplarlo en el host file para más adelante enumerarlo. Ahora, seguiremos enumerando un poco más el **SVN**, con el siguiente comando podremos ir moviendonos entre commits:
```
# svn up -r 2
Updating '.':
D    moved.txt
A    deploy.ps1
Actualizado a la revisión 2.
```

---------
#### Information Leakage  
Encontramos un archivo nuevo que no estaba antes, dentro de el encontramos credenciales utilizadas para windows con su formato **SecureString** correspondiente, pero además, vemos la contraseña en texto plano:
```powershell
$user = "nathen" 
$plain = "wendel98"
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
```

#### VHost Fuzzing - Gobuster  
Como tenemos un posible dominio a nuestra disposición, podemos ir fuzzeando por subdominios para adelantar un poco el trabajo. Lo haremos con **Wfuzz** pero se puede hacer de igual manera con **Gobuster**:
```ruby
# wfuzz -c --hc=404,400 --hh=703 -u "http://worker.htb" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.worker.htb' -t 100
[...]
000000248:   200        170 L    542 W      6495 Ch     "alpha"                                                   
000003240:   200        355 L    1408 W     16045 Ch    "story"                                                   
000005060:   200        397 L    1274 W     14803 Ch    "cartoon"                                                 
000009488:   200        111 L    398 W      4971 Ch     "lens"     
[...]
```

Encontramos 4 posibles subdominios los cuales contemplaremos en el host files para su posterior enumeración:

--------------------------
#### Azure DevOps Enumeration

En la pagina que encontramos en la nota, vemos que se nos solicita una contraseña, la cual, de primeras podriamos decir que la tenemos gracias al **Information Leak**, podemos proceder a iniciar sesión:
![[Pasted image 20230830203904.png]]

Una vez dentro, vemos el dashboard tipico de **Azure**:
![[Pasted image 20230830204027.png]]

Podemos ver muchos elementos de trabajos disposibles:
![[Pasted image 20230830204108.png]]

Además de un proyecto al que pertenecemos:
![[Pasted image 20230830204127.png]]

---------
#### Abusing Azure DevOps - Creating a Branch 
Vemos además, que dentro del proyecto tenemos capacidad de escritura. Esto nos facilita ciertas cosas, como la que vamos hacer a continuación. 

Vamos agregar una nueva rama al proyecto y vamos a escoger el repositorio de **Alpha** (el cual es un subdominio que enumeramos con anterioridad):
![[Pasted image 20230830204610.png]]

----------
#### Abusing Azure DevOps - Playing with existing Pipelines [RCE]
Al intentar subir una webshell y visitar la pagina, vemos que no existe y esto es dado a que no son los mismos proyectos, estamos en diferentes carpetas. Sin embargo, arriba del todo vemos un mensajito que nos indica que podemos crear un **Pull Request**:
![[Pasted image 20230901211325.png]]

Al darle a crear un **Pull Request** se nos envia a una pagina donde podemos configurar algunos aspectos del **Commit** que haremos, podemos pasar de todo y dale a a **Create**:
![[Pasted image 20230901221551.png]]

Esto nos redirige a una pagina donde vemos el estatus del proyecto, arriba hay un combo que al presionarlo nos muestra distintas acciones:
![[Pasted image 20230901221626.png]]

Si elegimos **Approve** observamos que nos lo aprueban. Ahora, le daremos a **Set auto-complete** y presionaremos **Set auto-completa** para confirmar loas cambios:
![[Pasted image 20230901221758.png]]

Y nos salta el siguiente aviso:
![[Pasted image 20230901221811.png]]

Al visitar denuevo la rama principal, podemos ver que nuestra **Web Shell** no existe. Bueno, cuando esto sucede una cosa que podemos hacer es aprovecharnos de los **PipeLines**. A un costado del dashboard vemos una sección de nombre **PipeLine** que al darle click se nos desplega algunas opciones, vamos a darle donde dice **Builds**. Dentro podemos elegir la que dice **Alpha-CI** y darle al boton que dice **RUN**:
![[Pasted image 20230901221845.png]]

Se nos abre la siguiente ventana en la cual podemos configurar algunas cosas. Vamos a setear donde dice **Branch** a nuestra rama creada con anterioridad(donde subimos la webshell):
![[Pasted image 20230901221920.png]]

Y le damos a aceptar. Veremos que el proyecto intenta cargarse y al hacerlo volveremos a visitar el repositorio principal y veremos que ahora si que existe nuestra webshell en la rama principal:
![[Pasted image 20230901222123.png]]

Asi que ahora podemos visitar `alpha.worker.htb/cmd.aspx` y deberia existir:
![[Pasted image 20230901222139.png]]

--------
#### IIS Exploitation
Ahora que tenemos capacidad remota de comandos, podemos intentar subir **nc.exe** y aprovecharnos de este para mandarnos una **Reverse Shell**.

---------
#### Elevating our Azure DevOps privilege  
Una vez en la maquina, podemos intentar listar los recursos compatidos a nivel de red de **SMB**:
```bash
c:\windows\system32\inetsrv>net share
net share

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share                     
IPC$                                         Remote IPC                        
W$           W:\                             Default share                     
ADMIN$       C:\Windows                      Remote Admin                      
The command completed successfully.
```

Vemos una carpeta de nombre **Sites** que de primera nos llama la atención dado que es aqui donde se suben los proyectos que antes vimos. Tambien hay una carpeta de nombre **snvrepos** que al ingresar a el, vemos que existen dos carpetas que saltan a la vista con nombre **conf** y **db**:
```
W:\svnrepos\www>ls
ls
README.txt
conf
db
format
hooks
locks
```

Dentro de la carpeta **conf** vemos que hay un archivo de nombre **Password** que al leerlos nos muestra algunas credenciales:
```
type passwd
type passwd
### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.

[users]
nathen = wendel98
nichin = fqerfqerf
nichin = asifhiefh
noahip = player
nuahip = wkjdnw
oakhol = bxwdjhcue
owehol = supersecret
paihol = painfulcode
parhol = gitcommit
pathop = iliketomoveit
pauhor = nowayjose
payhos = icanjive
perhou = elvisisalive
peyhou = ineedvacation
phihou = pokemon
quehub = pickme
quihud = kindasecure
rachul = guesswho
raehun = idontknow
ramhun = thisis
ranhut = getting
rebhyd = rediculous
reeinc = iagree
reeing = tosomepoint
reiing = isthisenough
renipr = dummy
rhiire = users
riairv = canyou
ricisa = seewhich
robish = onesare
robisl = wolves11
robive = andwhich
ronkay = onesare
rubkei = the
rupkel = sheeps
ryakel = imtired
sabken = drjones
samken = aqua
sapket = hamburger
sarkil = friday
```

Vemos la contraseña de **robisl** el cual, pudimos ver con anterioridad que se trata de un usuario a nivel de sistema. Además, al hacerle un `net user robisl` nos percatamos de que pertenece al grupo **Remote Management Use**:
```
C:\Users\robisl\Documents> net user robisl
User name                    robisl
Full Name                    Robin Islip
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2020-04-05 21:27:26
Password expires             Never
Password changeable          2020-04-05 21:27:26
Password required            No
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2023-09-02 07:32:43

Logon hours allowed          All

Local Group Memberships      *Production           *Remote Management Use
Global Group memberships     *None
The command completed successfully.

```

Asi que podemos conectarnos como este usuario con **Evil-WinRM**. Ahora podemos leer la flag del usuario de bajos privilegios:
```
C:\Users\robisl\Documents> type ..\Desktop\user.txt
bb4a93eae18bff4a7f5b929ee88d4aa4
```
Con estas mismas credenciales, también podemos iniciar sesión en el **Azure DevOps** pero ahora como un usuario con privilegios maximos.

-----------
#### Abusing Azure DevOps - Creating a new Pipeline  
En el **Azure DevOps** podemos consultar la sección de seguridad para ver a que tipo de grupo pertenecemos y vemos que pertenecemos al grupo **Build Administrators**:
![[Pasted image 20230901223433.png]]

Iremos a la sección de **PipeLines** y le daremos a crear uno nuevo. Vamos a seleccionar el primero:
![[Pasted image 20230901223517.png]]

Seleccionaremos el unico repositorio existente e iremos hacia abajo y seleccionaremos **Starter PipeLine**:
![[Pasted image 20230901223615.png]]

Dentro, vemos un archivo **.yml**. Hay una sección de nombre **Script** aqui, podemos definir un comando a ejecutar a nivel de sistema:
![[Pasted image 20230901223655.png]]

Le damos a **Save And Run** habiendo seleccionado la opcion **Create a new branch for this commit and start a pull request** pero al hacerlo, vemos que nos salta este error:
![[Pasted image 20230901223714.png]]

Lo que haremos simplemente es ir a ver los agentes disponibles(dado que esta intentar cargar **default**) y colocar el nombre correspondiente para que el archivo puede ejecutarse:
![[Pasted image 20230901224020.png]]

Y ahora si, al crearlo podremos ver el output correspondiente en la seccion de logs:
![[Pasted image 20230901224129.png]]

Habiendo confirmado la ejecucion remota de comando, podemos aprovecharnos de que tenemos el **nc** arriba de la maquina para entablarnos otra revese shell pero ahora a traves del **.yml**
![[Pasted image 20230901224145.png]]




