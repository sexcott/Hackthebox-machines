## Tecnicas utilizadas
-   HTTP Request Smuggling Exploitation (Leak Admin Cookie)
-   Cookie Hijacking
-   Information Leakage
-   AWS Enumeration
-   AWS Secrets Manager
-   AWS Key_management Enumeration
-   AWS KMS Decrypting File
## Procedimientos
-  User Emnumeration
- Gitea exploit search
- Register in the web
- Pasar la acicon de crear una nota, de verla y de eliminarla asi como la de crear comentario por burpsuite 
- Abusar de Smugglin con la informacion que nos brinda Nathan
- Cookie leaked
- Information leaked - Creds for gitea
- ID_RSA leaked from Commits in Gitea
- Procmon Bash scripting
- AWS - Log Management
- Bash scripting Secrets dump
- User Pivoting
- Bash scripting Decrypt file aws
```bash
!/bin/bash

# declaramos un array con los posibles algoritmos de desencriptado(esto nos lo brinda aws en su panel de ayuda)
declare -a algorithm=($values)

# Creamos un bucle que itere entre cada posible algoritmo
for i in ${algorithm[@]}; do

# Creamos otro bucle y a la vez listamos las keys de aws
	aws --endpoint-url="$ip" kms list-keys | grep KeyId | awk $last-argument | tr -d '""' | tr -d ',' | while read key_id; do
	
	echo -e "Probando con el key_id: $key_id\n el algoritmo: $i"
	aws --endpoint-url="$ip" kms decrypt --ciphertext-blob $file --key_id "$key_id" --encryption-algorithm "$i" 
	
	
	done
done
``` 
- Root password find