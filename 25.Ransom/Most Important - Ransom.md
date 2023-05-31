## Tecnicas utilizadas
- Login Bypass (Type Juggling Attack) 
- Decrypting a ZIP file (PlainText Attack - Bkcrack) - CONTI RANSOMWARE
## Procedimiento
- Se acontece un *Type Juggling* por la forma en la que se nos permite enviar los datos. Por detras, se compara el input del usuario con una cadena, al cambiar el tipo de dato a comparar por *true* nos da el login.
- Uso de *Bkcrack* para decriptar el archivo. Esto sucede por que al efectuar un listado de los archivos del comprimido ``7z l $archivo -slt`` podemos ver que el metodo del comprimido es **ZipCrypto Deflate**.
