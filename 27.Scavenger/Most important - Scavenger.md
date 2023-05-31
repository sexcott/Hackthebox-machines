## Tecnicas utilizadas
- **Domain Zone Transfer(AXFR)**
- **SQLI(ERROR BASED)**
- **ABUSING ROOTKIT** 
## Procedimiento
- VirtualHosting
- AFXR attack
- Probar conectarse al servicio por nc
- SQLi for ERROR BASED``') $query#``
- Mas transferencia de zona
- Fuzz sobre los dominios
- Scriptear una psudo consola para aprovechar el RCE
![[Pasted image 20221029163457.png]]
- Tirar por ftp con las credenciales encontradas
- Tirar por la bandeja de correo
- Tirar denuevo por ftp
- Virtual Hosting
- Tirar de tshark para el archivo .pcap encontrado
![[Pasted image 20221029165747.png]]
![[Pasted image 20221029165929.png]]
- Tirar de nuevo por ftp 
- Usar radare2 para hacer ingenieria inversa al archivo root.ko
	1. **aaa**. Analyze All 
	2. **afl**. Para filtrar por funciones del archivo
	3. **pdf**. para inspeccionar una funcion(*colorcar una @ antes de la funcion*)
- Encontrar la palabra clave para el rootkit

 