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
    - [TCP Protokol](#tcp-protokol)
    - [UDP Protokol](#udp-protokol)
    - [Funkce poll](#funkce-poll)
  - [Implementace projektu](#implementace-projektu)
    - [Obsah souborů](#obsah-souborů)
    - [Zpracování vstupních argumentů](#zpracování-vstupních-argumentů)
    - [Způsob zahájení komunikace](#způsob-zahájení-komunikace)
    - [Příjmání a odesílání zpráv](#příjmání-a-odesílání-zpráv)
    - [Kontrola syntaxe zpráv](#kontrola-syntaxe-zpráv)
    - [Validace zpráv dle konečného automatu](#validace-zpráv-dle-konečného-automatu)
    - [Blokování uživatelského vstupu](#blokování-uživatelského-vstupu)
    - [Ztráta příchozích paketů u UDP](#ztráta-příchozích-paketů-u-udp)
    - [Kontrola čísla příchozích paketů u UDP](#kontrola-čísla-příchozích-paketů-u-udp)
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

Ke kompilaci programu stačí zadat příkaz make (ve složce se zdrojovými soubory), který vytvoří spustitelný soubor `./cmuchac`
Ten lze následně spustit s následujícími parametry:

| Argument                  | Hodnota               | Význam                 |      Popis                                                    |
|---------------------------|-----------------------|------------------------|---------------------------------------------------------------|
| `-i OR --interface`       | Od uživatele/chybí*   | Název rozhraní         | Rozhraní, na kterém bude analyzátor pracovat                  |
| `-t OR --tcp`             |                       | Parametr TCP           | Filtrování TCP paketů (volitelně doplněno parametrem port**)  |
| `-u OR --ucp`             |                       | Parametr UCP           | Filtrování UDP paketů (volitelně doplněno parametrem port**)  |
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

Všechny argumenty lze zadat v jakémkoliv pořadí a akceptovaná čísla v argumentech jsou celá čísla. Pro spuštění analyzátoru paketl je nutné specifikovat rozhraní, na kterém bude pracovat. (Výpis rozraní viz Pozn. *).

Pozn. * Pokud rozhraní není specifikováno, je vypsán seznam dostupných rozhraní a program ukončen (rovněž v případě spustění programu bez argumentů).

Pozn. ** Parametrem port je myšlen `-p` nebo`--port-source` nebo `--port-source`

Pozn. *** Pokud není číslo specifikování, je výhozí hodnota 1. Pokud je zadáno číslo 0, analyzátor pracuje dokud není ukončen zkratkou CTRL+C.

Mezi parametry `--port-source` a `--port-source` je logický vztah `OR` a tyto parametry nelze kombinovat s parametrem `-p`, žádný parametr typu `port` nelze zadat bez parametru `tcp` nebo `udp`.

Příklad (analyzátor pracuje na rozhraní eth0 a sleduje vešekeré pakety s odchozím/příchozím portem 443, paketů zachytí a vypíše 5): 

```sh
./cmuchac -i eth0 --tcp -p 443 -n 5
```

### Vypisované informace
* `/auth <username> <key> <displayname>` 
Ověření totožnosti při připojení na server. Nejprve je nutné zadat uživatelské jméno, klíč (secret) a následně přezdívku, tedy jméno, které bude použito pro veřejné vystupování na serveru.
* `/rename <displayname>` Změní přezdívku, pod kterou uživatel posílá zprávy
* `/join <channellID>` Připojí se do jiného chatovacího kanálu
* `/help` Vypíše seznam podporovaných příkazů

## Stručná teorie k programu

### TCP Protokol
TCP protokol je protokol transportní vrstvy používán na spolehlivou výměnu dat. TCP umožňuje zasílání kontinuálního proudu bytů a přenos je spojovaný a spolehlivý, což se pojí s vyšší režíí. Aby data vůbec mohla být zasílána je nutné vytvořit spojení, které se děje v pomocí tzv. 3-way handshake mechanismu. TCP protokol zajišťuje, že zprávy odeslané z jednoho zařízení dorazí do druhého zařízení ve stejném pořádí jako byly odeslány. Pokud je v TCP zjištěna ztráta paketu je automaticky spuštěn proces opětovného odeslání. Jednotlivé zprávy jsou odděleny \r\n, aby jej chatovací klient mohl rozlišit

### UDP Protokol
UDP protokol je protokol transportní vrstvy, který nezajišťuje spolehlivou výměnu dat. UDP je na bázi "best effort delivery", který znamená, že u dat není zaručeno pořadí doručení paketů ani to, že data budou doručena v pořádku. Narozdíl od TCP nemusí navázat žádné spojení před odesláním samotných dat, nemá žádné mechanismy pro opětovné odesílání dat nebo potvrzení přijetí a tyto věci jsou tak řešeny specificky v chatovacím klientovi (opětovné odeslání zprávy, vypršení timeoutu). 

### Funkce poll
Funkce poll je funkce standardní knihovny jazyka C, která slouží ke sledování více file descriptorů současně na přicházející události z různých zdrojů. V kontextu chatovacího klienta je přicházející událostí příchozí zpráva od serveru na socket nebo čtení uživatelského vstupu, přičemž funkce poll není blokující a není nutný vícevláknový přístup v programování. Tato funkce je nutná, jelikož např. samotné čekání na zprávu je blokující operace a uživatel by tak musel čekat na zprávu od serveru, která ale není v daném okamžiku vůbec nutná.

## Implementace projektu

### Obsah souborů
Projekt je rozdělen do několik zdrojových souborů a díky programovacímu jazyku C++ je napsán se snahou využití objektově orientovaného programování.
* `main.cpp a main.hpp` - Funkce main a funkce pro korektní ukončení programu s dealokací paměti, statická třída pro odchycení CTRL-C
* `socket.cpp a socket.hpp` - Třída socket pro uchovávání informací o socketu, jeho tvorby a záník
* `arg_parser.cpp a arg_parser.hpp` - Statická třída pro zpracování vstupních argumentů
* `messages.cpp a messages.hpp` - Abstraktní třída NetworkMessage a jednotlivé podtřídy pro TCP a UDP zprávy
* `clients.cpp a clients.hpp` - Abstraktní třída NetworkClient a jednotlivé podtřídy pro TCP a UDP klienta

### Zpracování vstupních argumentů
Na začátku programu dochází ke zpracování argumentů od uživatele pomocí statické metody `parse_args` a jejich uložení do specifické struktury, v případě nezadaných volitelných argumentů jsou dané hodnoty nastaveny na výchozí a v případě zadání chybného atributu například příliš vysokého čísla portu nebo špatně zvoleného transportního protokolu je program ukončen s chybou.

### Způsob zahájení komunikace
Po zpracování argumentů dochází dle parametru typu protokolu k vytvoření instance TCP či UDP klienta a volání odpovídající metody, která zahají hlavní logiku programu. Následně pro oba klienty platí, že dochází k vytvoření socketu a volání metody `dns_lookup`, která pro případné zadané doménové jméno najde odpovídající IP adresu, v opačném případě se program ukončí. U TCP je navíc ještě zavolána funkce `connect`, která se serverem naváže stabilní spojení (narozdíl od UDP). V neposlední řadě dojde k vytvoření struktury pro funkci poll a její naplnění file descriptory pro socket a standardní vstup.

### Příjmání a odesílání zpráv
Veškerá komunikace se děje v jediném `while loopu`, kdy podmínka kontroluje zdali je příchozí událost ze standardního vstupu či jde o příchozí zprávu ze serveru a dojde k pokračování v odpovídající větvi. Příjmání zpráv je u TCP řešeno pomocí funkce `recv` a dochází k načítání po 1 bytu, dokud není nalezen ukončovač `/r/n`, u UDP je načitání prováděno pomocí funkce `recvfrom`, jelikož po úspešném příjetí zprávy je potřeba změnit port, na který budou následující zprávy odesílány. Zpráva je narozdíl od TCP načtena naráz, jelikož zpráva do něj přijde vždy 1 (u TCP by takto mohlo v bufferu skončit zpráv více). Kvůli zmíněné změně portu pro UDP je používáná funkce `sendto` a pro TCP pouze funkce `send`.

### Kontrola syntaxe zpráv
Během příjmání a odesílání zpráv dochází simultánně ke kontrole zpráv od uživatele, které jsou kontrolovány pomocí funkce `check_user_message`, zdali se jedná o příkaz a následně zformátovány do vhodného tvaru pro odeslání v závislosti na TCP/UDP protokolu pomocí funkce `process_outgoing_message` a rovněž dochází ke kontrole zpráv od serveru (funkce `process_inbound_message`), které jsou rozpoznány a předány ke kontrole dále.

### Validace zpráv dle konečného automatu
Po úspěšné kontrole příchozí zprávy dochází k ověření, že příchozí zpráva může být v daném stavu přijata (výčet stavů automatu je definován pomocí `enum` stavů, stavy `ERR` a `BYE` nejsou přímo implementovány z důvodu jejich nepotřebnosti), v pozitivním případě dochází k jejímu výpisu na odpovídající standardní výstup, v opačném případě dochází k chybě vedoucí k poslání chybové hlášky zpět k serveru nebo rovnou ukončení programu. Rovněž odesílání zpráv může stavy FSM nastavovat (poslání `auth` zprávy udělá přechod do `AUTH` stavu).

### Blokování uživatelského vstupu
Pokud dojde k odeslání zprávy, který vyžaduje odpověď tj. `CONFIRM` a `REPLY` u UDP a `REPLY` u TCP, dojde k zablokování vstupu od uživatele (respektive poll nebude brát v potaz uživatelský vstup). Po přijatí očekáváné zprávy dojde opět k odblokování a zpracování zpráv, které mohl uživatel v mezičase zadat.

### Ztráta příchozích paketů u UDP 
Kvůli podstatě UDP komunikace zmíněné dříve je u UDP klienta nastaven na socket časový interval , který určuje dobu, do které na jakoukoliv odeslanou uživatelskou zprávu musí přijít zpráva typu `CONFIRM`. Pokud do daného intervalu zpráva nepřijde, je zvýšen čítač pokusů odeslané zprávy a zpráva je odeslána znovu. Tento proces se opakuje do té doby než je dosažen maximální limit počtu opětovně odeslaných zpráv a program je ukončen. Na potvrzovací zprávu se čeká i v případě odeslání zprávy `BYE` od klienta. Správné a včasné přijetí zprávy `CONFIRM` zajišťuje funkce `handle_timeout`. V případě, že před zprávou `CONFIRM` dorazí zpráva jiného typu, je zpracována a zvalidována odpovídajícím způsobem popsaným výše.

### Kontrola čísla příchozích paketů u UDP
U UDP komunikace může dojít k přijetí zprávy s duplicitním `MessageID`. V takovém případě je daná zpráva zahozena, a tedy ignorována. Validace probíhá tím způsobem, že u každé přijaté zprávy je její `MessageID` uloženo do vektoru `seen_ids`. U každé následující přijaté zprávy je nejprve nahlédnuto do tohoto vektoru a v případě nalezení daného identifikátoru je zpráva ignorována.

### Ukončení programu
Ukončení programu je realizováno pomocí příkazu CTRL-C, příkazu CTRL-D (tedy poslání konce souboru) nebo pokud je konec v souladu s konečným automatem ze zadání projektu, tedy např. server pošle `BYE` zprávu. V každém případě se volá funkce `exit_program`, která dle předaných parametrů rozhodne, zdali je třeba ještě před koncem poslat `BYE` zprávu (pokud ano, je zpráva poslána a v případě UDP je také očekávána zpráva `CONFIRM`), program ukončí a dealokuje paměť. 

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
## Zdroje
- Linux manual page - poll(2). [online]. [cit. 2024-04-01]. Dostupné z: https://man7.org/linux/man-pages/man2/poll.2.html
- [RFC9293] Eddy, W. Transmission Control Protocol (TCP) [online]. Srpen 2022. [cit. 2024-04-01]. DOI: 10.17487/RFC9293. Dostupné z: https://datatracker.ietf.org/doc/html/rfc9293
- [RFC894] Hornig, C. A Standard for the Transmission of IP Datagrams over Ethernet Networks [online]. Duben 1984. [cit. 2024-04-01]. DOI: 10.17487/RFC894.Dostupné z: https://datatracker.ietf.org/doc/html/rfc894
- Transmission Control Protocol. In: *Wikipedia: the free encyclopedia*. [online]. 31. 1. 2024. [cit. 2024-04-01]. Dostupné z: https://cs.wikipedia.org/wiki/Transmission_Control_Protocol
- User Datagram Protocol. In: *Wikipedia: the free encyclopedia*. [online]. 18. 11. 2023. [cit. 2024-04-01]. Dostupné z: https://cs.wikipedia.org/wiki/User_Datagram_Protocol
- DOSTÁL R. Sockety a C/C++: funkce poll a závěr. [online].  [cit. 2024-04-01]. Dostupné z: https://www.root.cz/clanky/sokety-a-c-funkce-poll-a-zaver
- IPK Project 1: Client for a chat server using IPK24-CHAT protocol [online]. [cit. 2024-04-01]. Dostupné z: https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%201
