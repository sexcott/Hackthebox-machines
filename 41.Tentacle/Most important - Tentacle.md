**Squid proxy**: Servidor web con cache

- En el servidor web del squid proxy se proporciona nombres de domino y un nombre de subdominio
- Intento de ataque de transferencia de zona con *dig* 
- Uso de proxychain para pasar a través del squid proxy ``http $IP $Port``
- Lanzar nmap con el parametro -sT(Tcp Connect Scan) para poder utilizar proxychain
- Aplicar fuerza bruta con *dnsenum* para ver subdominios existentes
![[Pasted image 20221020232153.png]]
![[Pasted image 20221020232741.png]]
- Pasamos por la interfaz interna de squid proxy indicandolo en el proxychain como ``http $localhost $port``
![[Pasted image 20221020233644.png]]
![[Pasted image 20221020234127.png]]
Una vez pasando por:
1. El squid proxy de la maquina .
2. La propia interfaz del squid proxy.
3. El squid proxy del domino encotrado(que no es alcanzado desde fuera)
encontramos una pagina web la cual podemos visualizar si tramitamos una petición por curl.
- Buscar por wpad( *inaccesible* ) sin acceder a la URL predeterminada encontrada en google.
![[Pasted image 20221020235449.png]]
* Buscar a través del host encontrado con nmap para buscar puertos disponibles
![[Pasted image 20221021000005.png]]
- Buscar vulnerabilidad en searchsploit por el puerto 22 y modificar el rcto de este por un usuario valido para poder ejecutar comandos desde la maquina victima.
- Enumerar usuarios kerberos con *kerbrute*.
- Configurar kerberos y eliminar los parametros innecesarios en la ruta /etc/krb5.conf
![[Pasted image 20221021162356.png]]
- Intentar conectarse por kerberos con el usuario ``kinit $Usuario
- Observamos las tareas cron
- Abusamos del .k5login
 ![[Pasted image 20221021164048.png]]
 - por ultimo, miramos los archivos pertenecientes a nuestro usuario(**admin**) y encontramos keytab, el cual podemos utilizar con el comando: ``klist -k $PATHKEYTAB
 - nos conectamos a la interfaz de kerberos con ``kadmin -kt $PATHKEYTAB -p $PRINCIPALTOCONNECT
 - Desde la interfaz de kerberos admin, creamos un principal para el usuario root ``addprinc root@REALCORP.HTB
 - Usamos ksu, utilizamos la contraseña definida y pa dentro.
