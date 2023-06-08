-------------
- Tags: #brute-force #password-crack #cms-abuse #built 
-------------
## Tecnicas utilizadas
- Bludit CMS Exploitatio  
- Bypassing IP Blocking (X-Forwarded-For Header)  
- Directory Traversal Image File Upload (Playing with .htaccess)  
- Abusing sudo privilege (CVE-2019-14287)
-----------------
## Procedimiento

![[Pasted image 20230608085510.png]]

Comenzamos enumerando el CMS, encontramos archivos ocultos gracias a la creacion de dicionarios apartir de las palabras que se encuentran en la pagina principal. Usamos *cewl* para facilitar la creacion de diccionario.
Usamos el script de fuerza bruta que se encuentra en searchsploit.
Con el usuario y la contraseña, ingresamos al dashboard.
Usamos el exploit de *Path Transversal* para subir un *.htaccess* y un evil.png(que contiene codigo php), el *.htaccess*
tiene el bypass para que el *.png* se interprete como php.
Una vez dentro de la maquina, buscamos desde */var/www/* por contraseñas de forma recusiva. Encontramos la de hugo pero esta cifrada, asi que hacemos uso de *CrackStation* y damos con su contraseña.
Podemos abusar del */bin/bash* ya que tiene se me permite ejecutarlo como root gracias a la configuracion de sudoers.