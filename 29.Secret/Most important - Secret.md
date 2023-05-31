## Tecnicas utilizadas
- Code Analysis  
- Abusing an API  
- Json Web Tokens (JWT)  
- Abusing/Leveraging Core Dump [Privilege Escalation]
## Procedimiento
- Hacemos una petición por post a la API para registrar un usuario nuevo(*Mandarlo en formato JSON con el respectivo Content-Type*)
- Intentamos listar el contenido de la API de las rutas */priv* y */logs* pero al parecer solo el usuario "theadmin" puede hacerlo.
- Descargamos el Source que nos ofrece la pagina e inspeccionamos el codigo, también podemos echar un ojo a los logs ya que existe un *.git*. Con el secreto descubierto, podemos crear nuestro propio JWT en *https://JWT.io 
- Con el Web token creado, podemos listar lo que antes no podiamos de la ruta */priv* y */logs* ya que en el codigo podemos observar que solo valida que el campo *name* solo tiene que llamarse *theadmin* y los demas campos no los valida.
- Observamos que podemos ejecutar comandos con la api de logs ya que el input del usuario no esta sanitizado y podemos alterar la variable *file* para introducir un valor y colarle con comando despues de un *;*, geransmos una reverse shell.
- Listamos por binarios SUID y encontramos una llamado *count* que cuenta los caracteres de un archivo.
- En el archivo no compilado, podemos ver que tiene habilitado el *Core Dump*, asi que si llegaramos a provocar una exepción, podriamos leer en texto plano lo que esta leyendo el binario, este reporte se almacena en */var/crash/* 
- El reporte lo podemos leer con la herramienta que viene instalada por defecto en linux que lleva por nombre **apport-unpack**. Este nos crea una carpeta con ciertos archivos, pero el que nos importa es el llamado *CoreDump*, que listando las strings podemos leer de manera clara el contenido del archivo leido por el binario.