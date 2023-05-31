## Tecnicas utilizadas
- PHP Deserialization Attack 
- Abusing Race Condition
## Procedimiento
- Enumeracion con el panel de login de *WP*
- Fuzz por extensiones de posibles backups
- Dentro del backup, encontramos un archivo que nos hace creer que podemos aprovechar la deserealizacion que esta ocurriendo.
![[Pasted image 20221115235536.png]]
- Serealizamos la data que queremos que el servidor deserealice.
- Encontramos un script con privilegio de sudoers, aprovechamos y secuestramos el archivo al que mete en la clave autorizada para meter nuestra clave publica
![[Pasted image 20221116131121.png]]
