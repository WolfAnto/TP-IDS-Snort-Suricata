# TP-IDS-Snort-Suricata


![image](https://user-images.githubusercontent.com/73076854/228902772-0b711fe5-d78f-4632-b2c8-380be839addb.png)


VM 1 :
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

VM 2 :
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
iptables -t nat -F 
iptables -A OUTPUT -o eth1 -j DROP
apt-get install iptables-persistent 
iptables-save > /etc/iptables/rules
```
![image](https://user-images.githubusercontent.com/73076854/228929630-523f4063-1b41-48fb-bd25-9f20b6982f83.png)

```
apt install suricata
apt install suricata-oinkmaster-updater
apt install suricata-update
```

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

```
nano /lib/systemd/system/suricata.service 
Ajouter a la de la ligne "ExecStart" : -i br0
```
![image](https://user-images.githubusercontent.com/73076854/228929897-1defafc9-b97a-4923-945d-1aa85de83fbe.png)

```
/etc/init.d/suricata restart
```

```
ping YOUR_INTERNET_IUT_IP
```

dans une autre console : 
```
tail -f /var/log/suricata/fast.log 
```
![image](https://user-images.githubusercontent.com/73076854/228930267-b65c154e-c9aa-4690-8acd-2c267437d3e0.png)

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
## Aucune Alerte ne marche
![image](https://user-images.githubusercontent.com/73076854/228930415-49fa0125-a47a-46e7-a8bc-867d0d8a27cb.png)

```
wget -O splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.0.4.1/linux/splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb"
```

```
dpkg -i splunk-9.0.4.1-419ad9369127-linux-2.6-amd64.deb
```

```
cd /opt/splunk/bin
```

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

VM Backtrack (Carte en pont) :
![image](https://user-images.githubusercontent.com/73076854/228930607-e20e5517-d60b-4ff2-92de-0e76d3266031.png)

```
snort –dev –i eth0
```

```
snort -b -i eth0 -l ./ -L snort.pcap
```

```
snort –dev snort.pcap.1147077043 (attention au path)
```

ou

```
wireshark -r snort.pcap.1147077043
```

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
```

```
cd /etc/snort/rules
```

```
snort -vde -c snort.conf
```
