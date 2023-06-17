--------
- Tags: #memcache #openEMR #sql #sqli-errorbased #linux #docker #docker-group 
----------
## Tecnicas utilizadas

- Information Leakage (Code Inspection)  
- Abusing OpenEMR  
- Broken Access Control  
- Authentication Bypassing (Abusing the registration panel)  
- SQL Injection - Error Based [SQLI]  
- OpenEMR Authentication Exploit (RCE)  
- Memcache information Leakage
- Docker abuse

## Procedimiento
![[Pasted image 20230615000843.png]]

El escaneo en nmap da como resultado los siguientes puertos abiertos:
 ![[Pasted image 20230615093721.png]]
 
SI hacemos un whatweb a la pagina principal podemos ver las tecnologias que corren por detras:

![[Pasted image 20230615093833.png]]

------------
####  Information Leakage (Code Inspection)  

En la pagina principal, no hay gran cosa, si vamos a login y nos logueamos(credenciales encontradas en un script de js) tampoco podemos ver nada. Si vamos al apartado de autor, vemos que el creador tiene otra pagina *HMS*, si colocamos el dominio en */etc/hosts* vemos que nos resuelve a otra pagina:


La pagina tiene corriendo como un CMS *OpenEMR*,  es un software para administrar registros medicos.

-----------
#### Abusing OpenEMR

Si hacemos una busqueda con *searchsploit* podemos ver que contiene vulnerabilidades:

Cuando suceda esto, podemos tirar de google y utilizar algun wraper para filtrar por documentos *pdf*, esto nos puede mostrar reportes detallados de las vulnerabilidades del CMS.

-----------------
#### Broken Access Control  

Vemos que hay una vulnerabilidad de tipo *Broken Access Control*, si como url a visitar *admin.php* nos muestra un panel que en principio no se nos deberia de poder mostrar.

----------
#### Authentication Bypassing (Abusing the registration panel)  

Si fuzzeamos un poco la raiz del proyecto, vemos que existe una ruta de nombre *Portal* si la visitamos podemos observar que es otra pagina para autenticarnos. Sin embargo, si le damos a registrar y posteriormente colocamos en la URL una de las paginas a visitar, nos dejara visualizarla sin siquiera estar registrado.

-------------------------------
#### SQL Injection - Error Based [SQLI]  

Hay algunas rutas en especial donde se antontecen algunas inyeciones SQL, podemos aprovecharnos de estas para intentar dumpear todas las bases de datos.

--------------
#### OpenEMR Authentication Exploit (RCE)  

Una vez dumpeada la contraseña del usuario administrador, podemos proceder a ejecutar comandos de manera remota.
Podemos cojer algún script de los encontrados en *searchsploit*  para abusar de esta vulnerabilidad.

---------------
#### Memcache information Leakage

Hay un usuario con nombre **ash** del cual tenemos su contraseña, asi que podemos pivotear a ese usuario. Si hacemos un *netstat -nat* podemos ver que esta el puerto *11211*, que usualmente pertenece a **memcache**. 
De aqui, podemos obtener las credenciales del usuario *Luffy* con las cuales podemos conectarnos por *SSH*

#### Docker Abuse

Podemos ejecutar docker, asi que podemos tirar de GTObins para escalar privilegios.
