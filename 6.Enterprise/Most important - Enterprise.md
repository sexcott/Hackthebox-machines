## Tecnicas utilizadas
- WordPress Lcars Plugin SQLI Vulnerability SQL Injection (boolean-based blind, error-based, time-based blind) 
- WordPress Exploitation [www-data] (Theme Edition - 404.php Template)
- Joomla Exploitation [www-data] (Template Manipulation) 
- Docker Breakout 
- Ghidra Binary Analysis Buffer Overflow (No ASLR - PIE enabled) [RET2LIBC] (Privilege Escalation)
## Procedimiento
- Listar usuarios
- Inspeccionar el certificado SSL
- Listar el robots existente
- Fuzzear por directorios
- Tirar de **SQLMAP** para el archivo DB expuesto ``sqlmap -u $URL --dbs --batch``
- Dumpear informacion existente en la base de datos
- **Expresion regular**: '/^\\s*$/d'
- **Proceso extra:** Intentar dumpear los post de la pagina
- Ganamos acceso a los dos contenedores gracias a los dos CME, esto a traves de sus templates
- Bash scripting para encontrar hosts
- Bash scripting para encontrar los puertos de los hosts encontrados
- Inyectar un php malicioso a la web
- Transferir el binario que estaba expuesto
- Correr el programa con ltrace
- Utilizar **Ghidra** para analizar el binario
	1. Crear un proyecto
	2. Importar file
- **Dato:** La función *SCANF* no es seguro para proporcionar un input al usuario
- Al momento de desbordar el buffer, podemos sobreescribir otros registros.
- Tirar de **GDB** para analizar el desbordamiento del buffer
- Printear muchas "AAA" para que se acontezca, podemos utilizar **Python** ``python -c "print 'A'*$int"
- Tenemos que lograr que EIP(*Instruction Pointer*) apunte a donde se nos plazca
- Descrubir cuantas A's tiene que haber hasta antes de sobreescribir el EIP - *RET* - 
- Utilizar **checksec** para ver las protecciones del binario
- **ret2libc**: EIP -> system_addr + exit_addr + bin_sh_addrz
- Con *ldd* se pueden ver las librerias compartidas para dicho binario
- Para ver si esta habilitado el ASLR(**Aliatoriedad de las direcciones de la memoria**) podemos hacer el siguiente OneLiner `` for i in $(seq 1 150); do ldd $binarie | grep libc | awk `NF{print $NF}` | tr -d '()'; done``. Otra manera de de ver si esta activado, es consultar el siguiente binario */proc/sys/kernel/randomize_va_space* 
- Lo siguiente, es calcular cuantos caracteres son necesarios antes de sobreescribir el EIP. Podemos crear un patron de caracteres con GDB, de la siguiente manera ``pattern create 800``
- GDB puede calcular el offset automaticamente utilizando ``pattern offset $eip`` 
- Una vez tenemos el control del EIP, podemos hacer que apunte a las funciones antes mencionadas 
- Con GDB desde la maquina victima y corriendo el binario, podemos utilizar *info functions* para ver las funciones. Hacer un break en el main ``b *main`` y lo corremos ``r``. Habiendo hecho el Break, podemos printear la direcciones de *system* ``p system`` , la direccion de *exit* ``p exit``. Por ultimo, podemos buscar cadenas que contengan **SH**, lo logramos de la siguiente manera: ``find &system,+9999999,"sh"``. Podemos confirmar que es asi, viendo las strings de esa direccion ``x/s $direccion`` 
- Python Scripting ->
