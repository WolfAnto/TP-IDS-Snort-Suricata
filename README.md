## TP-IDS-Snort-Suricata

# Schéma du TP

![image](https://user-images.githubusercontent.com/73076854/228902772-0b711fe5-d78f-4632-b2c8-380be839addb.png)

# II ] Les sondes
Configuration VM 1 :
```
apt update && apt install bridge-utils
```
```
nano /etc/network/interfaces
```

```
auto eth0
auto eth1
auto br0
auto br0
iface br0 inet dhcp
    bridge_ports eth0 eth1
```
![image](https://user-images.githubusercontent.com/73076854/228929294-84da1cef-e12a-4c10-a91b-86c4c66bf8a0.png)

Configuration VM 2 :
```
nano /etc/network/interfaces
```

```
auto eth0
iface eth0 inet static
address 192.168.5.1/24
```
![image](https://user-images.githubusercontent.com/73076854/228929446-2141d257-91c1-4fe9-bb64-094b8c88e21a.png)


Vérifier le trafic (VM 1) :
```
tcpdump -nvx -i eth0
```
Désactivation du routage IP au niveau du noyau
```
nano /etc/sysctl.conf
net.ipv4.ip_forward=0
```
Une règle NetFilter/IPTables qui interdit toute émission de paquet sur l'interface activée en mode
stealth
```
iptables -t nat -F 
iptables -A OUTPUT -o eth1 -j DROP
apt-get install iptables-persistent 
iptables-save > /etc/iptables/rules
```
![image](https://user-images.githubusercontent.com/73076854/228929630-523f4063-1b41-48fb-bd25-9f20b6982f83.png)

# III] Suricata
Sur la VM 1 (Doutes ?!!)
Installer Suricata et mettre la liste de règles à journaux
```
apt install suricata
apt install suricata-oinkmaster-updater
apt install suricata-update
```

Ajouter vos propres règles
```
nano /etc/suricata/rules/my.rules
```

```
alert icmp any any -> any any (msg:"test icmp";)
alert ip any any -> any any (msg:"root attack"; content:"uid=0|28|root|29|";) 
```
![image](https://user-images.githubusercontent.com/73076854/228929728-41678ed7-c59f-4440-8fd9-6b6a7a3561e4.png)

```
nano /etc/suricata/suricata.yaml
```
[...]
```
default-rule-path: /etc/suricata/rules
rule-files:
 - my.rules
 - botcc.rules
```
![image](https://user-images.githubusercontent.com/73076854/228929823-7fa2e090-39b0-4f8b-87c6-c79cfae6524f.png)

Debug fichier de configuration Suricata. 
Avant cette manipulation, essayer de redemarrer Suricata
- Si il est en erreur, alors faire la manipulation ci-dessous
- Sinon ne pas faire la manipulation ci-dessous
```
nano /lib/systemd/system/suricata.service 
Ajouter a la de la ligne "ExecStart" : -i br0
```
![image](https://user-images.githubusercontent.com/73076854/228929897-1defafc9-b97a-4923-945d-1aa85de83fbe.png)

```
nano /etc/suricata/suricata.yaml
Remplacer "default par "br0" à la ligne 654
```
![image](https://user-images.githubusercontent.com/73076854/229089025-99d4a8a6-a061-4813-977f-6d8a562e3f97.png)

```
/etc/init.d/suricata restart
```

Test pour récupérer les log d'alertes
```
ping YOUR_INTERNET_IUT_IP
```

dans une autre console : 
```
tail -f /var/log/suricata/fast.log 
```
![image](https://user-images.githubusercontent.com/73076854/229088037-022bf961-dde3-40e0-aa12-c37819a6763b.png)

Tester les règles suivantes :
(Les ajouter dans "/etc/suricata/rules/my.rules")
1. Log des connexions FTP :
```
alert tcp any any -> any 21 (msg:"Connexion FTP détectée"; flow:established,to_server; content:"USER"; pcre:"/^USER\s[^rR].*/smi"; classtype:policy-violation; sid:1000001; rev:1;)
```

2. Alert d'une tentative de connexion avec USER root :
```
 tcp any any -> any 21 (msg:"Tentative de connexion avec USER root"; flow:established,to_server; content:"USER"; content:"root"; distance:0; classtype:attempted-admin; sid:1000002; rev:1;)
```

3. Alert de connexion HTTP vers Internet avec les mots sex, adults :
```
alert tcp any any -> any 80 (msg:"Mots interdits dans la requête HTTP"; flow:established,to_server; content:"GET"; http_uri; pcre:"/sex|adults/i"; classtype:policy-violation; sid:1000003; rev:1;)
```

4. Alert de connexions de l'Internet vers la base MySQL :
```
alert tcp any any -> any 3306 (msg:"Connexion entrante vers MySQL"; flow:established,to_server; content:"J"; offset:4; depth:1; classtype:attempted-recon; sid:1000004; rev:1;)
```

5. Alert d'un trafic Kazaa :
```
alert tcp any any -> any any (msg:"Trafic Kazaa détecté"; flow:established; content:"UserAgent\: KazaaClient"; classtype:policy-violation; sid:1000005; rev:1;)
```

Installation de Splunk
```
wget -O splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.0.4.1/linux/splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb"
```

```
dpkg -i splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb
```

```
cd /opt/splunk/bin
```

Démarrage/Configuration de Splunk
```
./splunk start
```
User : rt
Mdp : Rtlry85!

IHM de gestion : 
```
http://127.0.0.1:8000
```

Paramètres → entrées de données → fichier ajouter /var/log/suricata/eve.json

Search & Reporting : cliquez sur "résumé des données"
dans sources : sélectionner "/var/log/suricata/eve.json"

![image](https://user-images.githubusercontent.com/73076854/228933726-5e2e73b2-c073-46a2-9f8f-63ca79016c15.png)
![image](https://user-images.githubusercontent.com/73076854/229093969-d1d34145-f523-41b3-8d0a-49a365ad10b7.png)

# IV] Installation de Snort IDScenter

VM Backtrack (Carte en pont) :

![image](https://user-images.githubusercontent.com/73076854/228930607-e20e5517-d60b-4ff2-92de-0e76d3266031.png)

```
snort –dev –i eth0
```

```
snort -b -i eth0 -l ./ -L snort.pcap
```
![image](https://user-images.githubusercontent.com/73076854/229135531-83481863-9114-4472-9e0e-0add538abad5.png)

```
snort –r snort.pcap.1147077043 (attention au path)
```
![image](https://user-images.githubusercontent.com/73076854/229136114-fa7616f9-a758-4a84-aafa-3b057624c68f.png)


1. Connectez-vous à la base de données MySQL :
```
mysql -u root -p
```

2. Une fois connecté, listez les tables disponibles :
```
SHOW TABLES;
```

3. Sélectionnez la table 'data' et affichez son contenu :
```
SELECT * FROM data;
```

4. Pour quitter la console MySQL, tapez simplement :
```
EXIT;
```

Modifier le fichier /etc/snort/rules/snort.conf :
```
nano /etc/snort/rules/snort.conf
```
```
 HOME_NET, EXTERNAL_NET
```

```
Ajouter sensor_name=sonde_rt pour la sortie vers la base :
output database …. sensor_name=sonde1_rt
ne laisser que ses règles locales pour l’instant
# include $RULE_PATH/info.rules
# include $RULE_PATH/icmp-info.rules
include $RULE_PATH/local.rules
```

Ajouter une alerte avec le message « ALERT TEST ICMP » pour toutes les trames ICMP
dans le fichier local.rules :
```
nano /etc/snort/rules/local.rules
alert icmp any any <> any any ( msg:"test icmp";)
```

```
cd /etc/snort/rules
```

```
snort -vde -c snort.conf
```
