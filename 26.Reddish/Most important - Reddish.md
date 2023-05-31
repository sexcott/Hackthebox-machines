-  Icono representativo - Node red
- Probar con diferentes metodos la peticion
- Buscar la manera de establecer una reverse shell en node red
- Spawnear una bash con algun lenguaje de programación
- bash scripting host discovery
![[Pasted image 20221024092012.png]]
- Una vez con los hosts total descubierto para la red, fuzzeamos por los puertos de cada uno de estos.
![[Pasted image 20221024092809.png]]
- Uso de chisel para hacer port fortwarding
- El chisel se tiene que transferir por una funcion __CURL()
- Exponer el puerto 80 de un host encontrado anteriormente
- Exponert el puerto REDIS de un hosts encontrado anteriormente
- Enumerar las bases de datos de redis
- cargar una web shell con php a travès de redis
- Tirar de socat para entablar reverse shells encadenadas 
![[Pasted image 20221024100758.png]]
![[Pasted image 20221024101228.png]]
- Bash scripting para enumerar los comandos que se esten ejecuntando en intervalos regulares de tiempo
![[Pasted image 20221024102120.png]]
- Juegando con las wildcards de rsync para inyectar comandos
![[Pasted image 20221024103642.png]]
- Subimos una revershell a la web como root para establacernos una conexion como root automaticamente desde la web(la revershell debe apuntar al contenedor en el que corre sockat en un principio)
- enumerar con rsync 
- Subir una tarea cron con rsync
![[Pasted image 20221024104648.png]]
- La tarea cron se define de la siguiente forma 
![[Pasted image 20221024105550.png]]

- Descargar el socat mediante el socat que ya teniamos establecido en la primera maquina pwned! importante la funcion \_\_Curl() con anterioridad. Es necesario apuntar al puerto de escucha de la maquina atacante mediante el puerto de esuchaca de la maquina pwned
- Subir la reverse shell 
![[Pasted image 20221024105923.png]]
- Ponerse en escucha con sockat(se usa porq no esta nc en la maquina victima)
![[Pasted image 20221024110102.png]]
- df -h para listar las monturas
- Montar lo que se encuentre en alguna carpeta predefinida
![[Pasted image 20221024110940.png]]
- Como la montura, es de la maquina victima, tiene conectividad con nuestra maquina. Montamos una tarea cron como lo hicimos anteriormente y ejecutamos una revershell a intervalos regulares de tiempo