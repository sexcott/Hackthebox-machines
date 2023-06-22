-------
- Tags
-------
## Técnicas utilizadas
- Magento CMS Exploitation (Creating an admin user)  
- Magento - Froghopper Attack (RCE)  
- Abusing sudoers (Privilege Escalation)
## Procedimiento

![[Pasted image 20230619193543.png]]

El escaneo de **nmap** nos muestra los siguientes puertos:
```
# nmap -sCV -p80,22 10.10.10.140 -oN Ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-19 19:40 MST
Nmap scan report for 10.10.10.140
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6552bd24e8fa3817261379a12f624ec (RSA)
|   256 2e30007a92f0893059c17756ad51c0ba (ECDSA)
|_  256 4c50d5f270c5fdc4b2f0bc4220326434 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://swagshop.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.38 seconds
```
Si lanzamos un **whatweb** a la pagina principal, podemos ver las siguientes tecnologías corriendo por detrás:

```
# whatweb swagshop.htb
http://swagshop.htb [200 OK] Apache[2.4.18], Cookies[frontend], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], HttpOnly[frontend], IP[10.10.10.140], JQuery[1.10.2], Magento, Modernizr, Prototype, Script[text/javascript], Scriptaculous, Title[Home page], X-Frame-Options[SAMEORIGIN]
```

Vemos que esta utilizando de **CMS** magento. Según google, magento es:

	Magento es una plataforma de código abierto para comercio electrónico escrita en PHP. Fue desarrollada con apoyo de voluntarios por Varien Inc, una compañía privada con sede en Culver City, California. Varien publicó la primera versión del software el 31 de marzo de 2008

Básicamente magento se utiliza para el comercio.

#### Magento CMS Exploitation (Creating an admin user)




