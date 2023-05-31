## Tecnicas utilizadas
- Git Project Recomposition (.git) [Git-Dumper]  
- Abusing WordPress (SimplePie + Memcache) [PHP Code Analysis]  
- Memcache Object Poisoning (Gopherus + Deserialization Attack + RCE)  
- LDAP Enumeration (Apache Directory Studio - GUI)  
- Abusing LDAP to add an SSH Key  
- Abusing LDAP to modify the user group to sudo (Privilege Escalation)
## Procedimiento
- Virtual Hosting
- Using Git-Dumper para reconstruir el proyecto del .git
- GopherUS
- Serealizar la clase que vamos usar para aprovecharnos de memcache
- Asimilar el **Type** del debug
![[Pasted image 20221125152217.png]]
- Pasamos el type serializado por GopherUs
- Asimilar el **Name** del debug
![[Pasted image 20221125151918.png]]
- Mandamos la data serializada para que el servidor nos la deserialize y cree nuestro archivo pwned.php en los logs.
- Reutilizacion de contraseñas para la base de datos del Wp-Config.php
- Analisis del directorio /opt/
- Atenticarnos en ldap con la contraseña que encontramos en el .viminfo
- Realizamos una query 
![[Pasted image 20221125160211.png]]
- Utilizar **apachedirectorystudio** para la comodidad
- Local Port Forwarding para ldap
- Auntenticarnos de nuestro lado con los valores encontrados en el archivo .ldapsrc
![[Pasted image 20221125160817.png]]
- Añadimos un object class para lynik *ldap public key* para despues crear un atributo *ssh public key* y añadimos nuestra clave public. Cambimos el gidNumber para el numero identificador del grupo **Sudo** y ya podriamos convertirnos en **Root**
