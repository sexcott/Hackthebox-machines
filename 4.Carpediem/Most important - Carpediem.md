## Tecnicas utilizadas
- SQL inyection
- Change type_login with burpsuite bypass admin user
## Procedimiento
- Empece con el reconocimiento de la pagina, fuzzie primero por el vhost con **Gobuster**
- Encontre un dominio -> ``http://portal.carpediem.htb/``
- Hice fuzz en ambos dominios, en el principal no encontre nada util. En el segundo, encontre varias rutas que daban un 403 Forbiden, ya que se necesita autentificacion.
- Navegando por la pagina, vi varios parametros en la URL e intente un **Local File Inclusion**. Lamentablemente, no se pudo realizar.
- Por ultimo intente agregar una inyeccion SQL en los parametros GET de la url, empece con ``1' 1=1-- -`` y note que el mensaje de Scooter aparecia cuando la condicion era verdadera. Esto me dio la pista de que el campo era vulnerable a SQLi, intente una basada en Response pero no respondia. Intente con **SQLMAP** y al parecer si es vulnerable(pero basado en tiempo).
- No pude sacar gran cosa de la base de datos, solo 2 usuarios y 2 hashes que no daban a nada.
![[Pasted image 20221104194640.png]]
- Intente loguear en la pagina de Portal, pero no parecia ser la contraseña del usuario. 
- Intente con burpsuite en algunos campos hasta que di con el de update_user. Si se cambia el tipo de de login de 2 a 1, al parecer nos actualiza el perfil a administrador.
- Subi una un avatar con un revershell 
- Una vez dentro de la maquina, me percato que es un contenedor, para ser exacto `172.17.0.4` y me pongo a inspeccionar otros segmentos de la red. Cree un script para descubrir los host, encontre 5 aparte del mio y estos hosts tenian otros tantos puertos abiertos. Con chisel hice Remote Port Fordwarding y me traje la mayoria de puertos.
- De la ``172.17.0.5`` me traje el puerto **8118** que al parecer es un proxy llamado trudesk. Reutilizaron credenciales, y pude saberlo gracias al SQLi de el principio.
- En trudesk hay credenciales para conectarse a zoiper5, una app de llamadas de host. Obtenermos unas credenciales que sirven para conectarse por SSH
- 