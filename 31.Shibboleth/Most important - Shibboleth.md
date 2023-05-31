## Tecnicas utilizadas
-   Abusing IPMI (Intelligent Platform Management Interface)
-   Zabbix Exploitation
-   MariaDB Remote Code Execution (CVE-2021-27928)
## Procedimiento
- Fuzzing
- VHOST discovery
- UDP scanning with nmap
- Searching for UDP port find in the HackTricks
- Script en lua desde nmap para conocer la version del servicio que esta corriendo en el puerto por UDP.
- Utilizar el repo de CornField de *ipmi* para dumpear el hash de la contraseña de *Administrator* y posteriormente crackearlo.
![[Pasted image 20230106193852.png]]
- Reulitizacion de contraseñas para el portal de *zabbix*
- RCE desde *zabbix*
	1. Configuration -> Hosts -> Itezms.
	2. Crear un nuevo item. Abrimos el combo que nos ofece el apartado *Key* y buscamos por **system.run**(este nos permitira ejecutar comandos de manera remota)
	3. En el apartado *\<mode>*  lo cambiamos por *nowait* y en el campo *command* colocamos el comando deseado.
	4. test -> Get Value and Test
- Reutilización de contraseñas, denuevo. 
- *Expresion regular para eliminar salto de linea*: ``/^\s*$/d`` ``/^\s*$/d``
- Explotar la version en uso de MARIADB

