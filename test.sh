#!/bin/bash

KEY128="000102030405060708090a0b0c0d0e0f"
KEY192="000102030405060708090a0b0c0d0e0f1011121314151617"

echo -e "===== TEST DE NOTRE AES =====\n\n"

echo "Rappelons l'usage de notre aes :"
./bin/aes -h

echo -e "\n\nTest en deux partie :\n\t1) on va executer ./bin/aes -b pour effectuer un benchmark
        2) On va executer ./bin/aes sur trois modes de chiffrements distincts sur le fichier alice.sage avec la clé par defaut.
           On va ensuite se servir d'openssl pour tenter de dechiffrer nos chiffrés fait par nos soins.\t
           On lancera ensuite une commande linux permettant de comparé si les déchiffrés
        openssl obtenus correspondent bien au fichier de départ alice.sage. 
        Ce test sera fait sur des clés de taille 128 et 192"

echo -e "======================\n"
echo -e "1) BENCHMARK \n\n"
./bin/aes -b

echo -e "\n\n2) TEST AVEC OPENSSL (top 3 des trucs que j'ai appris en allant au ctf)\n"
echo -e "ECB :\n"
echo "Géneration d'un chiffré ecb avec notre binaire"
./bin/aes -e alice.sage -o alice_ecb.enc -m ECB
echo -e "\nOn se sert d'openssl pour déchiffrer notre chiffré !"
openssl enc -d -aes-128-ecb -in alice_ecb.enc -out ssl_dechiffre_ecb.txt -K "$KEY128"
echo -e "\nComparaison du fichier original alice.sage avec le dechiffré openssl"
if cmp -s alice.sage ssl_dechiffre_ecb.txt; then echo "ECB correct"; else echo "ECB incorrect"; fi

echo -e "\n\n>>>>> AES-128"

echo -e "\n\nCBC:\nGéneration d'un chiffré CBC avec notre binaire"
./bin/aes -e alice.sage -o alice_CBC.enc -m CBC
echo -e "\nOn extrait l'IV du chiffré en lisant les 16 premiers  avec xxd"
IV=$(xxd -l 16 -p -c 16 alice_CBC.enc)
echo "on extrait le vrai chiffré en soustrayant l'IV avec la commande dd:"
dd if=alice_CBC.enc of=alice_CBC_pur.enc bs=16 skip=1
echo -e "\nOn se sert d'openssl pour déchiffrer notre chiffré !"
openssl enc -d -aes-128-CBC -in alice_CBC_pur.enc -out ssl_dechiffre_CBC.txt -K "$KEY128" -iv "$IV"
echo "comparaison du fichier original alice.sage avec le dechiffré openssl"
if cmp -s alice.sage ssl_dechiffre_CBC.txt; then echo "CBC correct"; else echo "CBC incorrect"; fi

echo -e "\n\nCFB:\nGéneration d'un chiffré CFB avec notre binaire"
./bin/aes -e alice.sage -o alice_CFB.enc -m CFB
echo -e "\nOn extrait l'IV du chiffré en lisant les 16 premiers  avec xxd"
IV=$(xxd -l 16 -p -c 16 alice_CFB.enc)
echo "on extrait le vrai chiffré en soustrayant l'IV avec la commande dd:"
dd if=alice_CFB.enc of=alice_CFB_pur.enc bs=16 skip=1
echo -e "\nOn se sert d'openssl pour déchiffrer notre chiffré !"
openssl enc -d -aes-128-CFB -in alice_CFB_pur.enc -out ssl_dechiffre_CFB.txt -K "$KEY128" -iv "$IV"
echo "comparaison du fichier original alice.sage avec le dechiffré openssl"
if cmp -s alice.sage ssl_dechiffre_CFB.txt; then echo "CFB correct"; else echo "CFB incorrect"; fi



echo -e "\n\n2) TEST AVEC OPENSSL (top 3 des trucs que j'ai appris en allant au ctf)\n"
echo -e "ECB :\n"
echo "Géneration d'un chiffré ecb avec notre binaire"
./bin/aes -e alice.sage -o alice_ecb.enc -m ECB
echo -e "\nOn se sert d'openssl pour déchiffrer notre chiffré !"
openssl enc -d -aes-128-ecb -in alice_ecb.enc -out ssl_dechiffre_ecb.txt -K "$KEY128"
echo -e "\nComparaison du fichier original alice.sage avec le dechiffré openssl"
if cmp -s alice.sage ssl_dechiffre_ecb.txt; then echo "ECB correct"; else echo "ECB incorrect"; fi


echo -e "\n\nCBC:\nGéneration d'un chiffré CBC avec notre binaire"
./bin/aes -e alice.sage -o alice_CBC.enc -m CBC
echo -e "\nOn extrait l'IV du chiffré en lisant les 16 premiers  avec xxd"
IV=$(xxd -l 16 -p -c 16 alice_CBC.enc)
echo "on extrait le vrai chiffré en soustrayant l'IV avec la commande dd:"
dd if=alice_CBC.enc of=alice_CBC_pur.enc bs=16 skip=1
echo -e "\nOn se sert d'openssl pour déchiffrer notre chiffré !"
openssl enc -d -aes-128-CBC -in alice_CBC_pur.enc -out ssl_dechiffre_CBC.txt -K "$KEY128" -iv "$IV"
echo "comparaison du fichier original alice.sage avec le dechiffré openssl"
if cmp -s alice.sage ssl_dechiffre_CBC.txt; then echo "CBC correct"; else echo "CBC incorrect"; fi

echo -e "\n\nCFB:\nGéneration d'un chiffré CFB avec notre binaire"
./bin/aes -e alice.sage -o alice_CFB.enc -m CFB
echo -e "\nOn extrait l'IV du chiffré en lisant les 16 premiers  avec xxd"
IV=$(xxd -l 16 -p -c 16 alice_CFB.enc)
echo "on extrait le vrai chiffré en soustrayant l'IV avec la commande dd:"
dd if=alice_CFB.enc of=alice_CFB_pur.enc bs=16 skip=1
echo -e "\nOn se sert d'openssl pour déchiffrer notre chiffré !"
openssl enc -d -aes-128-CFB -in alice_CFB_pur.enc -out ssl_dechiffre_CFB.txt -K "$KEY128" -iv "$IV"
echo "comparaison du fichier original alice.sage avec le dechiffré openssl"
if cmp -s alice.sage ssl_dechiffre_CFB.txt; then echo "CFB correct"; else echo "CFB incorrect"; fi

echo -e "\n\n\n>>>>> AES-192"
./bin/aes -e alice.sage -o c_ecb192.enc -m ECB -k "$KEY192"
openssl enc -d -aes-192-ecb -in c_ecb192.enc -out ssl_ecb192.txt -K "$KEY192"
if cmp -s alice.sage ssl_ecb192.txt; then echo "ECB 192 CORRECT"; else echo "ECB 192 incorrect"; fi

./bin/aes -e alice.sage -o c_cbc192.enc -m CBC -k "$KEY192" 
IV=$(xxd -l 16 -p -c 16 c_cbc192.enc)
dd if=c_cbc192.enc of=c_cbc_pur192.enc bs=16 skip=1 status=none
openssl enc -d -aes-192-cbc -in c_cbc_pur192.enc -out ssl_cbc192.txt -K "$KEY192" -iv "$IV" 
if cmp -s alice.sage ssl_cbc192.txt; then echo "CBC 192 correct"; else echo "CBC 192 incorrect"; fi

./bin/aes -e alice.sage -o c_cfb192.enc -m CFB -k "$KEY192"
IV=$(xxd -l 16 -p -c 16 c_cfb192.enc)
dd if=c_cfb192.enc of=c_cfb_pur192.enc bs=16 skip=1 status=none
openssl enc -d -aes-192-cfb -in c_cfb_pur192.enc -out ssl_cfb192.txt -K "$KEY192" -iv "$IV" 
if cmp -s alice.sage ssl_cfb192.txt; then echo "CFB 192 correct"; else echo "CFB 192 incorrect"; fi