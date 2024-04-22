# Dokumentace IPK-24 ZETA: Network snifferu

**Autor:** Samuel Hejníček  
**Datum:** 22. dubna 2024  


## Obsah
- [Dokumentace IPK-24 ZETA: Network snifferu](#dokumentace-ipk-24-zeta-network-snifferu)
  - [Obsah](#obsah)
  - [Úvod](#úvod)
    - [Stručný popis](#stručný-popis)
    - [Spuštění programu](#spuštění-programu)
    - [Vypisované informace](#vypisované-informace)
  - [Stručná teorie k programu](#stručná-teorie-k-programu)
    - [ISO/OSI Model a průzkum paketů](#isoosi-model-a-průzkum-paketů)
    - [PCAP knihovna](#pcap-knihovna)
    - [Zachytávané protokoly](#zachytávané-protokoly)
  - [Implementace projektu](#implementace-projektu)
    - [Obsah souborů](#obsah-souborů)
    - [Zpracování vstupních argumentů](#zpracování-vstupních-argumentů)
    - [Nastavení analyzátoru paketů](#nastavení-analyzátoru-paketů)
    - [Zachytávání paketů a výpis informací](#zachytávání-paketů-a-výpis-informací)
    - [Ukončení programu](#ukončení-programu)
  - [Testování programu](#testování-programu)
    - [TCP klient](#tcp-klient)
    - [UDP klient](#udp-klient)
  - [Možná vylepšení](#možná-vylepšení)
  - [Zdroje](#zdroje)


## Úvod

Tento soubor je dokumentací k druhému projektu do předmětu [IPK], Počítačové komunikace a sítě, veškeré zdrojové soubory jsou dostupné [zde](https://git.fit.vutbr.cz/xhejni00/IPK_Project_2). Projekt je napsán jazyce C (standardu GNU99) a určen pro platformu Linux. 

### Stručný popis

Program slouží jako síťový analyzátor paketů na uživatelsky specifikovaném rozhraní (podporována pouze rozhraní typu Ethernet). Pakety na daném rozhraní zachytává dle uživatelem zadaného filtru (v podobě argumentů při spuštění programu) a vypíše o nich [užitečné informace](#vypisované-informace). Počet paketů, který analyzátor zachytí a vypíše je rovněž dán argumentem. Program končí po stisknutí CTRL+C nebo pokud dosáhl zachycení daného počtu paketů.

### Spuštění programu

Ke kompilaci programu stačí zadat příkaz make (ve složce se zdrojovými soubory), který vytvoří spustitelný soubor `./ipk-sniffer`
Ten lze následně spustit s následujícími parametry:

| Argument                  | Hodnota               | Význam                 |      Popis                                                    |
|---------------------------|-----------------------|------------------------|---------------------------------------------------------------|
| `-i or --interface`       | Od uživatele/chybí*   | Název rozhraní         | Rozhraní, na kterém bude analyzátor pracovat                  |
| `-t or --tcp`             |                       | Parametr TCP           | Filtrování TCP paketů (volitelně doplněno parametrem port**)  |
| `-u or --ucp`             |                       | Parametr UCP           | Filtrování UDP paketů (volitelně doplněno parametrem port**)  |
| `-p`                      | Od uživatele          | Číslo portu            | Filtrování dle zadaného portu (port je zdrojový nebo příchozí)|
| `--port-source`           | Od uživatele          | Číslo portu            | Filtrování dle zadaného portu (port je zdrojový)              |
| `--port-destination`      | Od uživatele          | Číslo portu            | Filtrování dle zadaného portu (port je odchozí)               |
| `--icmp4`                 |                       | Parametr ICMP4         | Filtrování ICMPv4 paketů                                      |
| `--icmp6`                 |                       | Parametr ICMP6         | Filtrování ICMPv6 paketů                                      |
| `--arp`                   |                       | Parametr ARP           | Filtrování ARP rámců                                          |
| `--ndp`                   |                       | Parametr NDP           | Filtrování ndp paketů (část ICMPv6)                           |
| `--mld`                   |                       | Parametr MLD           | Filtrování mld paketů (část ICMPv6)                           |
| `--igmp`                  |                       | Parametr IGMP          | Filtrování igmp paketů                                        |
| `-n`                      | Od uživatele/chybí*** | Počet paketů           | Při zapnutí programu analyzuje zadaný počet paketů            |
| `-h`                      |                       | Nápověda               | Vypíše nápovědu a skončí program.                             |

Všechny argumenty lze zadat v jakémkoliv pořadí a akceptovaná čísla v argumentech jsou celá čísla (pro port v rozmezí 0 až 65535 a pro n číslo větší nebo rovno 0). Pro spuštění analyzátoru paketl je nutné specifikovat rozhraní, na kterém bude pracovat. (Výpis rozraní viz Pozn. *).

Pozn. * Pokud rozhraní není specifikováno, je vypsán seznam dostupných rozhraní a program ukončen (rovněž v případě spustění programu bez argumentů).

Pozn. ** Parametrem `port` je myšlen `-p` nebo`--port-source` nebo `--port-source`. Mezi parametry `--port-source` a `--port-source` je logický vztah `OR` a tyto parametry nelze kombinovat s parametrem `-p`, žádný parametr typu `port` nelze zadat bez parametru `tcp` nebo `udp`.

Pozn. *** Pokud není číslo specifikováno, je výhozí hodnota 1. Pokud je zadáno číslo 0, analyzátor pracuje dokud není ukončen zkratkou CTRL+C.

Příklad (analyzátor pracuje na rozhraní eth0 a sleduje vešekeré pakety s odchozím/příchozím portem 443, paketů zachytí a vypíše 5): 

```sh
./ipk-sniffer -i eth0 --tcp -p 443 -n 5
```

### Vypisované informace

U každého zachycecného paketu, který prošel uživatelsky zadanám filtrem (filtr mohl být prázdný) jsou vypsány následující informace:

* `časová známka` ve formátu RFC 3339
* `zdrojová a cílová MAC adresa` jako řetězec, jednotlivé části adresy jsou oddělené dvojtečkou
* `délka rámce`v bytech
* `data paketu` v hexadecimální a ascii podobě kopírující vzhled používající aplkace [Wireshark](https://www.wireshark.org/)

Pokud existují:
* `zdrojová a cílová ip adresa` jako řetězec, pokud jde o ipv4 je vypsána v "dotted decimal" podobě, v případě ipv6 je vypsána v souladu s RFC 5952
* `zdrojový a cílový port` jako celé číslo

Specifické pro daný protokol:
* `doplňující informace` jako např. typ u ICMP4, ICMP6 či IGMP paketu

## Stručná teorie k programu

### ISO/OSI Model a průzkum paketů
Dle síťového modelu OSI můžeme síťovou komunikaci rozdělit na celkem 7 vrstev. Pro síťový analyzátor je důležitá hlavně 2. vrstva (linková), 3. vrstva (síťová) a 4. vrstva (transportní). Uživatelská data poslána po síti prochází zapouzdřením, kdy se na každé vrstvě přidá odpovídající hlavička protokolu (např. TCP nebo IP) podle typu dat a způsobu komunikace a tento proces postupuje od aplikační vrstvy až po fyzicku vrstvu, na které dochází k přenosu dat. U paketu (jednotka dat přenášená přes síťové rozhraní), který zachytí síťový analyzátor se postupuje opačným směrem, tedy nejprve je rozbalena hlavička Ethernetu na datalinkové vrstvě (z ní lze vyčíst například zdrojovou a cílovou MAC adresu) a následně se postupuje dále k hlavičce IP (z ní lze vyčíst např. zdrojovou a cílovou IP adresu) na třetí síťovou vrstvu, proces dále postupuje do vyšších vrstev. Tímto postupným "rozbalováním" dochází k průzkumu vlastností paketu. Postupná dekapsulace směrem od ethernetové vrstvy k vyšším je nutná, jelikož právě např. protokol TCP operuje na transportní vrstvě zatímco třeba protokol ARP na vrstvě linkové.

### PCAP knihovna
Jako knihovna poskytující vysokoúrovňové rozhraní pro zachytávání paketů byla použita knihovna PCAP. Tato knihovna nabízí všekeré potřebné funkce včetně vytvoření a spravování analyzátoru včetně jeho provozu v reálném čase. Její rozhraní umožňuje zachytit i pakety určené pro jiné cílové hosty a umožňuje číst a a zapisovat zachycené pakety ze/do souboru.

### Zachytávané protokoly
* `TCP` - Protokol transportní vrstvy používán na spojovaný a spolehlivý přenost dat. Zprávy odeslané a příjmané mezi zařízeními dorazí ve stejném pořadí jako byly odeslány. Spojení zajišťuje pomocí 3-way handshake mechanismu. 
  
* `UDP` - Protokol transportní vrstvy nezajišťující spolehlivou výměnu dat. Není zaručeno pořadí paketů ani to, že dorazí v pořádku.
  
* `ICMPv4 a ICMPv6` - Komunikační protokoly sloužící k odesílání komunikačních a chybových zpráv mezi zařízeními. Všechny zprávy mají svůj typ, kteý indentifikuje jejich obsah. Patří sem rovněž i pakety typu `NDP` a `MLD`, které jsou specifikovány právě jmenovaným typem (např. MLD používá hodnoty 130, 131, 132 a 143).
  
* `ARP` - Komunikační protokol sloužící k získání linkové adresy (v případě tohoto analyzátoru MAC adresy, tedy fyzické adresy počítače) pomocí známe IP adresy.
  
* `IGMP` - Protokol síťové vrstvy umožňující několika zařízením sdílet stejnou IP adresu, aby tato zařízení mohla příjmat stejná data (tedy používá podporu multicastu). Zařízení se připojují a odpoujují z tzv. multicastových skupin, která má sdílenou IP adresu.

## Implementace projektu

### Obsah souborů
Projekt je rozdělen do několik zdrojových souborů.
* `main.c` - Funkce main a funkce pro korektní ukončení programu (včetně zkratky CTRL + C) s dealokací paměti
* `argparser.c a argparser.h` - Funkce pro zpracování vstupních argumentů
* `sniffer.c a sniffer.h` - Funkce pro nastavení analyzátoru paketů včetně nastavení jehó filtru
* `prints.c a prints.h` - Funkce pro výpis potřebných informací o paketu

### Zpracování vstupních argumentů
Na začátku programu dochází ke zpracování argumentů od uživatele pomocí funkce `parse_args` a jejich uložení do specifické struktury. Pokud nebyly zadány žádné argumenty nebo byl zadán pouze argument pro rozhraní bez jeho hodnoty, je vypsán seznam dostupných rozhraní a program úspěšně ukončen. V případě zadání chybné hodnoty argumentu například příliš vysokého čísla portu nebo přímo neznámého argumentu je program rovněž ukončen, nýbrž s chybou.

### Nastavení analyzátoru paketů
Po zpracování argumentů dochází k zavolání funkce `sniff`, která má na starost veškerou činnost okolo analyzátoru. Ta nejprve zavolá pomocnou funkci `create_pcap_sniffer`, která vytvoří a aktivuje zmíněný analyzátor a zkontroluje, že datová linka je typu `ethernet` (jiná není podporována). Následně je volána funkce `apply_pcap_filter`, která ze vstupních argumentů uložených ve specifické datové struktuře vytvoří řetězec pravidel, která vloží do filtru, který je použit pro analyzátor.

### Zachytávání paketů a výpis informací
Samotné zachytávání paketů na daném rozhraní probíhá pomocí funkce `pcap_loop`, které lze rovnou specifikovat i počet paketů k odchycení. Tato funkce při zachycení paketu v volá funkci `packet_parser`, která již z paketu extrahuje konkrétní informace od časového razítka po zdrojový či cílový port (a další) a zajistí výpis těchto informací na standardní výstup.

### Ukončení programu
Ukončení programu během analýzy paketů je realizováno pomocí příkazu CTRL-C. V takovém případě se volá funkce `graceful_exit`, která dealokuje paměť pro síťový analyzátor a program ukončí. Pokud během tvorby analyzátoru nebo jeho nastavení došlo k chybě, je vypsána chybová hláška a program ukončen již v daném okamžiku.

## Testování programu
Testování probíhalo po celou dobu vývoje programu. Zahrnovalo jak kontrolu úniků paměti a původce neoprávněního přístupu do ní (pomocí funkce `valgrind`), tak nástroje díky kterým bylo možné dívat se na odeslané a přijaté zprávy klienta. Mezi testovací software patřily jak specializované nástroje (`netcat`, `wireshark`), tak např. referenční fakultní server nebo vlastní udp server. Všechny testy byly spouštěny na systému Ubuntu, který běžel v rámci `WSL 2` pod systémem Windows. Všechny příklady testů používají stejnou takřka sadu příkazů, jímž je ověření, poslání zprávy a ukončení spojení.

### TCP klient
Testování TCP klienta bylo o něco jednodušší než testování UDP klienta a to díky  tomu, že zprávy mezi serverem a klientem chodí v normální textové podobě, tak jak ji známe. Testování TCP klienta probíhalo přes:

1. [Netcat](https://netcat.sourceforge.net/) spuštěný na loopback rozhraní

    Testování pomocí netcatu pobíhalo tak, že v jednom terminálu byl spuštěn server (simulován právě pomocí netcatu) a v druhém terminálu byl spuštěn klient, který se na daný server připojil. Komunikace následně probíhala ručně, kdy byl na klientovi zadán příkaz nebo poslána zpráva a na netcatu byla ručně zadána odpověď. Tímto způsobem bylo možné otestovat vše, co TCP funkcionalita vyžadovala, jen bylo zdlouhavé psát zprávy od serveru ve správném formátu.

    Server byl spuštěn tímto příkazem:
    ```sh
    nc -4 -C -l -v 127.0.0.1 4567
    ```
    Klient byl spuštěn pomocí tohoto příkazu
    ```sh
    ./ipk24chat-client -t tcp -s localhost -p 4567
    ```

    V následující tabulce je zachycena komunikace mezi klientem a serverem ze strany klienta:
    ```sh
    /auth xlogin00 topsecret Samik
    Success: v poradku
    jsem overeny uzivatel
    /join jinykanal
    ahoj
    Failure: nepripojim te
    ^C
    ```

    V následující tabulce je komunikace zachycena pomocí ze strany serveru:
    ```sh
    Listening on localhost 4567
    Connection received on localhost 49096
    AUTH xlogin00 AS Samik USING topsecret
    REPLy OK is v poradku
    MSG FROM Samik IS jsem overeny uzivatel
    JOIN jinykanal AS Samik
    REPLY nok is nepripojim te
    MSG FROM Samik IS ahoj
    BYE
    ```
    Lze si všimnout, že zpráva ahoj zadána ihned po zprávě `JOIN` dorazila až poté, co server na zprávu odpověděl. Poté co se klient rozhodl ukončit spojení, které realizoval přes CTRL-C poslal ještě serveru zprávu `BYE`. Za zmínku také stojí, že server může poslat klíčová slova zprávy malými písmeny v souladu s gramatikou v zadání projektu.

    Jako speciální případy u testování pomocí netcatu jsem vybral:
    - případ, kdy zadá uživatel příkaz který neexistuje
    - délka jednoho z parametrů příkazu přesáhne určité hodnoty.
    - opětovná snaha o autorizaci po již úspěšně ověřené předešlé autorizace


    Všechny tyto případy jsou zachyceny v tabulce níže:
    ```sh
    /auth xhejni00 topsecret Samik
    Success: ok

    /prikaz
    ERR: Wrong command. Type /help for help

    /join Makovapanenkamelakobedusushismedvedem
    ERR: Wrong command syntax. Usage: /join {ChannelID}

    /auth xhejni00 topsecret Samik
    ERR: Already authorized.
    ```
    U žádného z příkazů nedojde k ukončení klienta, dojde pouze k vypsání chybové hlášky a je očekáváno opětovné zadání zprávy/příkazu, tedy v soulaldu se zadáním.  


2. Referenční server  
   
    Jako druhou možnost jak testovat projekt byl zvolen referenční fakultní server s doménovým jménem `anton5.fit.vutbr.cz`. Jeho výhodou oproti testování přes netcat je, že zprávy posílá automaticky a taky lze v reálném čase skutečně komunikovat s ostatními uživateli na tomto serveru.

    Na následující tabulce je zachycena kominikace na referenčním TCP serveru:
    ```sh
    /auth xlogin00 topsecret susenka
    Success: Authentication successful.
    Server: susenka joined discord.general.
    Server: jani joined discord.general.
    ahoj
    jani: ahoj
    /join jinam
    Success: Channel jinam successfully joined.
    ^C
    ```
    Testování na referenčním serveru bylo prováděno až ke konci projektu, jelikož testování přes locální netcat server bylo dostačující a nehrozilo, že bude server přehnaně zatížen kvůli možné chybě v kódu (while true loop).


### UDP klient
Testování UDP klienta bylo mnohem kompikovanější než u TCP, jelikož posílání zpráv je realizováno v binární podobě, a tak není možné snadno odpovídat zpět například pomocí netcat serveru a navíc je potřeba při nastaveném socket timeoutu odpovědět včas jinak je možné snadno dosáhnout limitu pro timeout a dojít tak u končení klienta. Přesto bylo realizováno několik možností jak spojení testovat.

1. Netcat na loopback rozhraní

    I přes úskalí UDP byl projekt částečně přes netcat testován, konkrétněji posílání zpráv přes UDP protokol. V takovém případě bylo možné vyčíst přijaté zprávy z netcat serveru, nicméně nebylo možné na ně odpovědět zpět (kvůli jejich formátu). Rovněž nastal problém s možnými timeouty, kdy po jejich implementaci nebylo možné netcat validně využívat, protože v daném časovém intervalu nemohla být doručena odpověď.
    Proto se stal netcat brzo nepřijatelným testovacím prostředím.  

    Server byl spuštěn s tímto příkazem (klient spuštěn stejně jako u TCP):
    ```sh
    nc -4 -u -l -v 127.0.0.1 4567
    ```

    Tabulka níže obsahuje zprávy přijaté na netcat serveru.
    ```sh
    Connection received on localhost 56489
    xloginsusenkatopsecretxloginsusenkatopsecretxloginsusenkatopsecretxloginsusenkatopsecret
    ```
    Z tabulky lze vyčíst ze server celkem 4x přijal autentizaci s danými parametry. Bohužel ale nebylo možné poslat odpověď, a tak v klientu vypršel timeout na `AUTH`zprávu a následně po odeslání zprávy `BYE` i na tuto zprávu viz tabulka:

    ```sh
    /auth xlogin topsecret susenka
    ERR: MAX TIMEOUTS REACHED.
    ERR: MAX TIMEOUTS REACHED.
    ```

2. Studentský UDP server
   
   UDP server běží na lokálním rozhraní a je vytvořený jedním ze studentů FIT dostupný [zde](https://github.com/okurka12/ipk_proj1_livestream/blob/main/ipk_server.py)
   Server dokáže komunikovat velice obdobným způsobem jako referenční fakultní server. Na každou zprávu posílá `CONFIRM` zprávy a každou odeslanou zprávu přepošle s jejím zněním zpět. Výhoda testování byla navíc, že `REPLY` zprávu poslal vždy z dynamického portu, kterému se následně klient musel přizpůsobit, aby mohl zprávu správně doručit zpět.

   Příklad komunikace se jmenovaným serverem ze strany klienta:
   ```sh
   /auth xlogin00 topsecret Samik
    Success: Hi, Samik, this is a successful REPLY message to your AUTH message id=0. You wanted to authenticate under the username xlogin00
    ahoj, jak to jde?
    Server: Hi, Samik, This is a reply MSG to your MSG id=1 content='ahoj, jak to jd...'
    /join jinykanal
    Success: Hi, Samik, this is a successful REPLY message to your JOIN message id=2. You wanted to join the channel jinykanal
    ^C
   ```

    Tabulka níže znázorňuje komunikaci, kterou vidí server:
    ```
    started server on 0.0.0.0 port 4567

    Message from 127.0.0.1:52002 came to port 4567:
    TYPE: AUTH
    ID: 0
    USERNAME: 'xlogin00'
    DISPLAY NAME: 'Samik'
    SECRET: 'topsecret'
    b'\x02\x00\x00xlogin00\x00Samik\x00topsecret\x00'
    Confirming AUTH message id=0
    sending REPLY with result=1 to AUTH msg id=0

    Message from 127.0.0.1:52002 came to port dyn2:
    TYPE: CONFIRM
    REF ID: 62889
    b'\x00\xf5\xa9'

    Message from 127.0.0.1:52002 came to port dyn2:
    TYPE: MSG
    ID: 1
    DISPLAY NAME: 'Samik'
    'ahoj, jak to jde?'
    b'\x04\x00\x01Samik\x00ahoj, jak to jde?\x00'
    Confirming MSG message id=1

    Message from 127.0.0.1:52002 came to port dyn2:
    TYPE: CONFIRM
    REF ID: 25477
    b'\x00c\x85'

    Message from 127.0.0.1:52002 came to port dyn2:
    TYPE: JOIN
    ID: 2
    DISPLAY NAME: 'Samik'
    CHANNEL ID: 'jinykanal'
    b'\x03\x00\x02jinykanal\x00Samik\x00'
    Confirming JOIN message id=2
    sending REPLY with result=1 to JOIN msg id=2

    Message from 127.0.0.1:52002 came to port dyn2:
    TYPE: CONFIRM
    REF ID: 25430
    b'\x00cV'

    Message from 127.0.0.1:52002 came to port dyn2:
    TYPE: BYE
    ID: 3
    b'\xff\x00\x03'
    Confirming BYE message id=3
    ```
3. [Wireshark](https://www.wireshark.org/)

    Pro zachycení komunikace mezi klientem a serverem byl rovněž použit program Wireshark s filtrací pro komunikaci UDP, kde byly díky rozšíření pro protokol IPK24-CHAT dobře vidět jednotlivé zprávy. Jako největší výhodu byla možnost zachytit správnou reakci klienta na dynamický port a jeho reakci. (Pro obrázky níže předpokládajme, že nejprve klient posíla zprávy na port 4567).
    
    ![Komunikace zachycená ve Wiresharku](image/wireshark1.jpg)

    Na obrázku výše lze vidět zprávu `REPLY`, která přišla z dynamického portu 46719.


    ![Komunikace zachycená ve Wiresharku](image/wireshark2.jpg)

    Na obrázku výše lze vidět zprávu `CONFIRM`, která odchází na daný dynamický port 46719.

4. Vlastní udp server
   
    Kvůli nemožnosti vlastní testování kombinace posílání zpráv a zároveň implementace čekání na TIMEOUT jednotlivých zpráv byl pro účely testování mnou vytvořen malý jednoduchý server v C++, který blokujícím způsobem čekal na zprávu a poté několik odesílal. Výhodou byla naprostá volnost v posílání zpráv (v daném binárním formátu). V tabulce níže je zachycena komunikace ze strany serveru (klasická posloupnost oveření a odeslání zprávy), kde je vždy v hex formátu vypsána příchozí a odchozí zpráva.

    ```sh
    UDP Server started on port 4567. Waiting for messages...
    INCOMING Message in hex: 02 00 00 78 6c 6f 67 69 6e 30 30 00 73 75 73 65 6e 6b 61 00 74 6f 70 73 65 63 72 65 74 00

    00 00 00 00
    Sent hex message back to client.

    01 00 05 01 00 00 6c 6c 00 00
    Sent hex message back to client.

    04 00 06 73 65 72 76 65 72 00 68 65 6c 6c 6c 00 00
    Sent hex message back to client.
    ```



5. Referenční fakultní server
   
    Jako poslední možnost testů byl zvolen fakultní referenční server, na kterém probíhalo tesstování obdobně jako u TCP varianty, server se chová korektně v souladu se zadáním, proto nebylo možné otestovat TIMEOUT na zprávy a podobné věci.


## Možná vylepšení
Chatovací klient není dokonalý a obsahuje několik věcí, které by mohly být v budocnu vylepšeny, mezi ně patří například:

* Vylepšení mechanismu timeoutů, kdy doba do vypršení timeoutu aktuálně nereflektuje skutečnou dobu, pokud před zprávou CONFIRM dorazí jiná zpráva
* Refaktorizace kódu, kdy je možné více sjednotit funkce pro hlavní logiku jak TCP tak UDP klienta, vyčlenění funkcí do dalších tříd (logika zpracovávání zpráv)
* Přídání dalších podporovaných příkazů
* Přidání časového razítka při odeslaných a přijatých zprávách
* 
## Zdroje
- [RFC3339] KLYNE, G. Date and Time on the Internet: Timestamps. [online]. Říjen 2002. [cit. 2024-04-22]. DOI: 10.17487/RFC3339. Dostupné z: https://datatracker.ietf.org/doc/html/rfc3339
- [RFC5952] KAWAMURA, Seiichi a Masanobu KAWASHIMA. A Recommendation for IPv6 Address Text Representation. [online]. Srpen 2010. [cit. 2024-04-22]. DOI: 10.17487/RFC5952. Dostupné z: https://datatracker.ietf.org/doc/html/rfc5952
- OSI model. In: *Wikipedia: the free encyclopedia*. [online]. 19. 4. 2024. [cit. 2024-04-22]. Dostupné z: https://en.wikipedia.org/wiki/OSI_model
- ZAORAL, K. Přenos informací (paketů). [online]. [cit. 2024-04-22]. Dostupné z: https://www.itnetwork.cz/site/zaklady/site-prenos-informaci-paketu
- CARSTENS, Tim. Programming with PCAP. [online]. [cit. 2024-04-22]. Dostupné z: https://www.tcpdump.org/pcap.html 
- Pcap(3PCAP) manual page. [online].  4. 3. 2024. [cit. 2024-04-22]. Dostupné z: https://www.tcpdump.org/manpages/pcap.3pcap.html
- Transmission Control Protocol. In: *Wikipedia: the free encyclopedia*. [online]. 31. 1. 2024. [cit. 2024-04-22]. Dostupné z: https://cs.wikipedia.org/wiki/Transmission_Control_Protocol
- User Datagram Protocol. In: *Wikipedia: the free encyclopedia*. [online]. 18. 11. 2023. [cit. 2024-04-22]. Dostupné z: https://cs.wikipedia.org/wiki/User_Datagram_Protocol
- Internet control message protocol. In: *Wikipedia: the free encyclopedia*. [online]. 9. 4. 2024. [cit. 2024-04-22]. Dostupné z: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
- CLOUDFARE. What is IGMP?. [online]. [cit. 2024-04-22]. Dostupné z: https://www.cloudflare.com/learning/network-layer/what-is-igmp/
- FORTINET. What is Address Resolution Procol (ARP)?. [online]. [cit. 2024-04-22]. Dostupné z: https://www.fortinet.com/resources/cyberglossary/what-is-arp