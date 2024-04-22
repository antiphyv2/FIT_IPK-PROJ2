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
    - [Testování zpracování argumentů](#testování-zpracování-argumentů)
    - [Test správné dealokace paměti po ukončení programu s CTRL + C](#test-správné-dealokace-paměti-po-ukončení-programu-s-ctrl--c)
    - [Testování odchycení a výpisu informací jednotlivých paketů](#testování-odchycení-a-výpisu-informací-jednotlivých-paketů)
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
| `--filter`                |                       | Parametr pro výpis     | Při zapnutí programu vypíše řetězec aplikovaný na filtr paketů|
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
Testování probíhalo po celou dobu vývoje programu. Zahrnovalo jak kontrolu úniků paměti a původce neoprávněního přístupu do ní (pomocí funkce `valgrind`), tak kontrolu správnosti výpisu informací paketů primárně pomocí porovnání výstupu s informacemi v programu [Wireshark](https://www.wireshark.org/) nebo kontrolu vstupních argumentů. Testování bylo prováděno v systému WSL (Windows Subsystem for Linux) s distribucí Ubuntu 22.04.3 LTS.

### Testování zpracování argumentů
Při testování argumentů byl důraz primárně na vytvořený řetězec následně vkládaný do filtru (čímž dojde ke kontroly většiny argumentů) a kontrola validního formátu čísel popřípadě kombinace argumentů.

1. Korektní spuštění programu s náhodnými validní argumenty

   Cílem bylo otestovat, zdali je filtr vytvořen se správnými filtrovacími parametry.
   Rozhraní `lo` bylo vybráno z dostupných rozhraní.

    Program byl spuštěn tímto příkazem:
    ```sh
    sudo ./ipk-sniffer -i lo -t --udp -p 23 --igmp --icmp6 --arp --filter
    ```
    Výpis programu:
    ```sh
    filter arguments: ((tcp or udp) and port 23) or arp or icmp6 and (ip6[40] == 128 or ip6[40] == 129) or igmp
    ```
    Je tedy vidět, že ve filtru jsou správně přidané argumenty zadané ze vstupu, které reflektují daný protokol i konkrétní specifický typ, konkrétně protokoly `TCP` a `UDP` v logické spojce `OR` a zároveň port 23, který může být odchozí i zdrojový. Mezi zbytkem argumentů opět platí logická spojka `OR` a u icmp6 lze ještě vidět filtrování pro konkrétní typy `ECHO REQUEST` a `ECHO REPLY`. Program následně bylo nutné ukončit pomocí CTRL+C, jelikož hledal pakety shodující se s daným filtrem.


2. Spuštění programu bez argumentů
   
    Cílem bylo otestovat korektní výpis dostupných rozhraní a následné ukončení programu.

    Program byl spuštěn postupně takto:
    ```sh
    sudo ./ipk-sniffer -i
    ```
    ```sh
    sudo ./ipk-sniffer
    ```
    Výpis programu:
    ```sh
    List of available network interfaces:
    1. interface: eth0
    2. interface: any, Description: Pseudo-device that captures on all interfaces
    3. interface: lo
    4. interface: docker0
    5. interface: bluetooth-monitor, Description: Bluetooth Linux Monitor
    6. interface: nflog, Description: Linux netfilter log (NFLOG) interface
    7. interface: nfqueue, Description: Linux netfilter queue (NFQUEUE) interface
    8. interface: dbus-system, Description: D-Bus system bus
    9. interface: dbus-session, Description: D-Bus session bus
    ```
    V obou případech byl výpis správný, tedy síťový analyzátor vypsal dostupná síťová rozhraní a ukončil svou činnost.

3.  Spuštění programu s nevalidními argumenety
   
    Cílem bylo celkem 2krát otestovat korektní pád programu včetně absenci úniků paměti (tedy správně dealokace).

    Spuštění programu č. 1 s následujícími parametry
    ```sh
    sudo ./ipk-sniffer -p 80
    ```
    Výpis programu:
    ```sh
    ==707456== Memcheck, a memory error detector
    ==707456== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
    ==707456== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
    ==707456== Command: ./ipk-sniffer -p 80
    ==707456==
    ERR: [ARGPARSER] Port cant be specified without TCP or UDP.

    ==707456==
    ==707456== HEAP SUMMARY:
    ==707456==     in use at exit: 0 bytes in 0 blocks
    ==707456==   total heap usage: 2 allocs, 2 frees, 93 bytes allocated
    ==707456==
    ==707456== All heap blocks were freed -- no leaks are possible
    ==707456==
    ==707456== For lists of detected and suppressed errors, rerun with: -s
    ==707456== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
    ```
    Z výpisu lze vyčíst, že nedochází k únikům paměti a dle očekávání je vypsána chybová hlaška, jelikož parametr `port` nemůže být zadán bez parametrů `TCP` či `UDP`.

    Spuštění programu č. 2 s následujícími parametry
    ```sh
    sudo valgrind ./ipk-sniffer --tcp -p 80000
    ```
      Výpis programu:
    ```sh
    ==708605== Memcheck, a memory error detector
    ==708605== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
    ==708605== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
    ==708605== Command: ./ipk-sniffer --tcp -p 80000
    ==708605==
    ERR: [ARGPARSER] Invalid number in port. Range is 0 - 65535.

    ==708605==
    ==708605== HEAP SUMMARY:
    ==708605==     in use at exit: 0 bytes in 0 blocks
    ==708605==   total heap usage: 2 allocs, 2 frees, 93 bytes allocated
    ==708605==
    ==708605== All heap blocks were freed -- no leaks are possible
    ==708605==
    ==708605== For lists of detected and suppressed errors, rerun with: -s
    ==708605== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
    ```
    Z výpisu lze vyčíst, že nedochází k únikům paměti a dle očekávání je vypsána chybová hlaška, jelikož parametr `port` je zadán mimo platné rozmezí.

### Test správné dealokace paměti po ukončení programu s CTRL + C
Cílem tohoto testu bylo zkontrolovat nepřítomnost úniků paměti při spuštění programu s validními argumenty následně odchytit několik paketů (zachytávání probíhalo "do nekonečna, tedy parametr n byl roven nule") a skončit pomocí klávesové zkratky CTRL + C.

  Program byl spuštěn následovně:
  ```sh
  sudo valgrind ./ipk-sniffer --tcp -i eth0 -n 0
  ```
  Výpis programu:
  ```sh
    ==711773== Memcheck, a memory error detector
    ==711773== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
    ==711773== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
    ==711773== Command: ./ipk-sniffer -i eth0 -n 0
    ==711773==
    timestamp: 2024-04-22T17:25:09.882+02:00
    src MAC: 00:15:5d:e7:8c:20
    dst MAC: 01:00:5e:00:00:fb
    frame length: 87
    src IP: 172.29.32.1
    dst IP: 224.0.0.251
    packet type: ipv4 UDP
    src port: 5353
    dst port: 5353

    0x0000: 01 00 5e 00 00 fb 00 15 5d e7 8c 20 08 00 45 00  ..^..... ].. ..E.
    0x0010: 00 49 58 10 00 00 ff 11 b6 79 ac 1d 20 01 e0 00  .IX..... .y.. ...
    0x0020: 00 fb 14 e9 14 e9 00 35 01 59 00 00 00 00 00 01  .......5 .Y......
    0x0030: 00 00 00 00 00 00 10 5f 73 70 6f 74 69 66 79 2d  ......._ spotify-
    0x0040: 63 6f 6e 6e 65 63 74 04 5f 74 63 70 05 6c 6f 63  connect. _tcp.loc
    0x0050: 61 6c 00 00 0c 00 01                             al.....

    timestamp: 2024-04-22T17:25:09.884+02:00
    src MAC: 00:15:5d:e7:8c:20
    dst MAC: 33:33:00:00:00:fb
    frame length: 107

    0x0000: 33 33 00 00 00 fb 00 15 5d e7 8c 20 86 dd 60 03  33...... ].. ..`.
    0x0010: 35 e1 00 35 11 ff fe 80 00 00 00 00 00 00 ed 1b  5..5.... ........
    0x0020: cc f5 c1 47 cc 21 ff 02 00 00 00 00 00 00 00 00  ...G.!.. ........
    0x0030: 00 00 00 00 00 fb 14 e9 14 e9 00 35 68 79 00 00  ........ ...5hy..
    0x0040: 00 00 00 01 00 00 00 00 00 00 10 5f 73 70 6f 74  ........ ..._spot
    0x0050: 69 66 79 2d 63 6f 6e 6e 65 63 74 04 5f 74 63 70  ify-conn ect._tcp
    0x0060: 05 6c 6f 63 61 6c 00 00 0c 00 01                 .local.. ...

    ... (další pakety)

    ^C==711773==
    ==711773== HEAP SUMMARY:
    ==711773==     in use at exit: 0 bytes in 0 blocks
    ==711773==   total heap usage: 33 allocs, 33 frees, 18,880 bytes allocated
    ==711773==
    ==711773== All heap blocks were freed -- no leaks are possible
    ==711773==
    ==711773== For lists of detected and suppressed errors, rerun with: -s
    ==711773== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
  ```
  Výpis ukazuje korektní dealokaci paměti i po několika odchycených paketech.

### Testování odchycení a výpisu informací jednotlivých paketů
Zachytávání jednotlivých paketů probíhalo buď na výchozím rozhraní WSL `eth0`, kde síťový analyzátor vypsal informace o paketu prakticky vždy (na rozhraní se stále něco děje a protokolem je vždy `TCP` nebo `UDP`) nebo na rozhraní `lo`, tedy loopback rozhraní. Výstup programu byl následně vždy porovnán s programem Wireshark, který rovněž poskytuje užitečné informace o odchyceném paketu a sloužil tak jako kontrola správnosti detekce typu paketu a kontrole správných výpisů.

1. Testování paketů protokolu TCP/UDP

   Cílem bylo otestovat, zdali síťový analyzátor správně zachytí TCP nebo UDP pakety (kvůli jejich stejnému výpisu jsou spojeny v 1 test) a vytiskne na standardní výstup správné informace. Jak bylo avizováno v odstavci výše, pakety obou typů byly zachytávány na rozhraní `eth0`, kde byly odchyceny automaticky (tedy jejich existence byla v režii OS).

    Program byl pro testování spuštěn tímto příkazem:
    ```sh
    sudo ./ipk-sniffer -i eth0 -t -- udp
    ```
    Výpis programu:
    ```sh
   timestamp: 2024-04-22T18:19:49.311+02:00
   src MAC: 00:15:5d:e7:8c:20
   dst MAC: 00:15:5d:a5:ba:2b
   frame length: 105
   src IP: 140.82.112.21
   dst IP: 172.29.36.121
   packet type: ipv4 TCP
   src port: 443
   dst port: 42090

   0x0000: 00 15 5d a5 ba 2b 00 15 5d e7 8c 20 08 00 45 00  ..]..+.. ].. ..E.
   0x0010: 00 5b 66 44 40 00 2d 06 1a 5b 8c 52 70 15 ac 1d  .[fD@.-. .[.Rp...
   0x0020: 24 79 01 bb a4 6a cb 7b eb 08 4c ba 11 77 80 18  $y...j.{ ..L..w..
   0x0030: 00 52 c5 e7 00 00 01 01 08 0a bf cd fd 89 6e 7b  .R...... ......n{
   0x0040: 0f cb 17 03 03 00 22 f7 34 b3 83 f0 47 d7 95 f7  ......". 4...G...
   0x0050: e9 77 d3 b9 0f b3 64 0d 0c 77 9a c4 ca b6 74 51  .w....d. .w....tQ
   0x0060: e9 69 b4 55 aa 8a b1 ef 08                       .i.U.... .
   ```

   Screenshot odchyceného paketu z programu Wireshark:
   [Paket zachycený ve Wiresharku](image/Wireshark_TCP.png)

   Ze snímku lze vyčíst shodnost MAC adres, zdrojových a cílových portů, zdrojových a cílových MAC adres a počet zachycených bytů, test tedy proběhl úspěšně a síťový analyzátor úspešně detekoval TCP paket.

2. Testování paketů protokolu ICMPv4

   Cílem bylo otestovat, zdali síťový analyzátor správně zachytí ICMPv4 pakety na rozhraní `lo`. Na detekci tohoto paketu byl použit poměrně jednoduchý test a to příkaz `ping` na adresu lokálního rozhraní `127.0.0.1`. V takovém případě se na rozhraní vyskytují 2 druhy ICMPv4 paketů a to `ECHO REQUEST` a `ECHO REPLY`, které měl za úkol analyzátor zachytit.
    Program byl pro testování spuštěn tímto příkazem:
    ```sh
    sudo ./ipk-sniffer -i lo --icmp4 -n 2
    ```
    Výpis programu:
      ```sh
      timestamp: 2024-04-22T18:32:06.778+02:00
      src MAC: 00:00:00:00:00:00
      dst MAC: 00:00:00:00:00:00
      frame length: 98
      src IP: 127.0.0.1
      dst IP: 127.0.0.1
      packet type: ipv4 ICMP
      icmp type: Echo request
      icmp code: 0

      0x0000: 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00  ........ ......E.
      0x0010: 00 54 60 89 40 00 40 01 dc 1d 7f 00 00 01 7f 00  .T`.@.@. ........
      0x0020: 00 01 08 00 72 42 00 12 00 01 06 91 26 66 00 00  ....rB.. ....&f..
      0x0030: 00 00 8e e0 0b 00 00 00 00 00 10 11 12 13 14 15  ........ ........
      0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25  ........ .. !"#$%
      0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35  &'()*+,- ./012345
      0x0060: 36 37                                            67

      timestamp: 2024-04-22T18:32:06.778+02:00
      src MAC: 00:00:00:00:00:00
      dst MAC: 00:00:00:00:00:00
      frame length: 98
      src IP: 127.0.0.1
      dst IP: 127.0.0.1
      packet type: ipv4 ICMP
      icmp type: Echo reply
      icmp code: 0

      0x0000: 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00  ........ ......E.
      0x0010: 00 54 60 8a 00 00 40 01 1c 1d 7f 00 00 01 7f 00  .T`...@. ........
      0x0020: 00 01 00 00 7a 42 00 12 00 01 06 91 26 66 00 00  ....zB.. ....&f..
      0x0030: 00 00 8e e0 0b 00 00 00 00 00 10 11 12 13 14 15  ........ ........
      0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25  ........ .. !"#$%
      0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35  &'()*+,- ./012345
      0x0060: 36 37                                            67
      ```

   Screenshot odchyceného paketu z programu Wireshark:
   [Paket zachycený ve Wiresharku](image/Wireshark_ICMP4.jpg)

    Ze snímků lze mimo hodnot vyčtených i v předchozím testu (MAC adresy, IP adresy, ...) i druh ICMP zpráv, v jednom případě REQUEST a v jednom REPLY.

3. Testování paketů protokolu ICMPv6

    *ECHO REQUEST A REPLY*

    V prvním testu bylo cílem otestovat, zdali síťový analyzátor správně zachytí ICMPv6 pakety na rozhraní `lo`. Na detekci tohoto paketu byl použit příkaz `ping` na ipv6 adresu lokálního rozhraní `::1`. V takovém případě se na rozhraní vyskytují 2 druhy ICMPv6 paketů a to `ECHO REQUEST` a `ECHO REPLY`, které měl za úkol analyzátor zachytit (stejně jako v případě icmpv4). 

    Program byl pro testování spuštěn tímto příkazem:
    ```sh
    sudo ./ipk-sniffer -i lo --icmp6 -n 2
    ```
    Výpis programu:
      ```sh
      timestamp: 2024-04-22T18:44:30.548+02:00
      src MAC: 00:00:00:00:00:00
      dst MAC: 00:00:00:00:00:00
      frame length: 118
      src IP: ::1
      dst IP: ::1
      packet type: ipv6 ICMP
      icmp6 type: Echo request
      icmp6 code: 0
      icmp6 checksum: 18306

      0x0000: 00 00 00 00 00 00 00 00 00 00 00 00 86 dd 60 05  ........ ......`.
      0x0010: 3e a0 00 40 3a 40 00 00 00 00 00 00 00 00 00 00  >..@:@.. ........
      0x0020: 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00  ........ ........
      0x0030: 00 00 00 00 00 01 80 00 82 47 00 13 00 01 ee 93  ........ .G......
      0x0040: 26 66 00 00 00 00 21 5b 08 00 00 00 00 00 10 11  &f....![ ........
      0x0050: 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21  ........ ...... !
      0x0060: 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31  "#$%&'() *+,-./01
      0x0070: 32 33 34 35 36 37                                234567

      timestamp: 2024-04-22T18:44:30.548+02:00
      src MAC: 00:00:00:00:00:00
      dst MAC: 00:00:00:00:00:00
      frame length: 118
      src IP: ::1
      dst IP: ::1
      packet type: ipv6 ICMP
      icmp6 type: Echo reply
      icmp6 code: 0
      icmp6 checksum: 18305

      0x0000: 00 00 00 00 00 00 00 00 00 00 00 00 86 dd 60 08  ........ ......`.
      0x0010: 08 1c 00 40 3a 40 00 00 00 00 00 00 00 00 00 00  ...@:@.. ........
      0x0020: 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00  ........ ........
      0x0030: 00 00 00 00 00 01 81 00 81 47 00 13 00 01 ee 93  ........ .G......
      0x0040: 26 66 00 00 00 00 21 5b 08 00 00 00 00 00 10 11  &f....![ ........
      0x0050: 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21  ........ ...... !
      0x0060: 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31  "#$%&'() *+,-./01
      0x0070: 32 33 34 35 36 37                                234567
      ```

   Screenshot odchyceného paketu z programu Wireshark:
   [Paket zachycený ve Wiresharku](image/Wireshark_ICMP6.jpg)

    Ze snímků lze mimo hodnot vyčtených i v předchozím testu (MAC adresy, IP adresy, ...) i druh ICMP zpráv, v jednom případě REQUEST a v jednom REPLY.

    *NDP*

    V druhém testu bylo cílem otestovat pakety typu `ndp`, které patří pod icmpv6. Zachytávání tentokrát probíhalo na rozhraní `eth0`. Pro poslání paketů na toto rozhraní použit python skript využivající knihovnu [Scapy](https://scapy.net/). Tento skript poslal paket NDP typu 135, tedy `neighbor solicitation` na multicastovou adresu `ff02::1:ff00:1` používanou právě pro zprávy tohoto typu a byl poslán ze zdrojové link local adresy rozhraní `eth0`.

    Program byl pro testování spuštěn tímto příkazem:
    ```sh
    sudo ./ipk-sniffer -i eth0 --ndp
    ```
    Výpis programu:
      ```sh
      timestamp: 2024-04-22T19:04:19.45+02:00
      src MAC: 00:15:5d:a5:ba:2b
      dst MAC: 33:33:ff:a5:ba:2b
      frame length: 86
      src IP: fe80::215:5dff:fea5:ba2b
      dst IP: ff02::1:ff00:1
      packet type: ipv6 ICMP
      icmp6 type: [NDP] Neighbor solicitation
      icmp6 code: 0
      icmp6 checksum: 581

      0x0000: 33 33 ff a5 ba 2b 00 15 5d a5 ba 2b 86 dd 60 00  33...+.. ]..+..`.
      0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 02 15  ... :... ........
      0x0020: 5d ff fe a5 ba 2b ff 02 00 00 00 00 00 00 00 00  ]....+.. ........
      0x0030: 00 01 ff 00 00 01 87 00 45 02 00 00 00 00 fe 80  ........ E.......
      0x0040: 00 00 00 00 00 00 02 15 5d ff fe a5 ba 2b 01 01  ........ ]....+..
      0x0050: 02 15 5d fe a5 ba                                ..]...
      ```

   Screenshot odchyceného paketu z programu Wireshark:
   [Paket zachycený ve Wiresharku](image/Wireshark_NDP.jpg)

    Na snímku je sice paketů spousta nicméně ten s více informaci odpovídá stejnému paketu, který zachytil síťový analyzátor se správným typem. 

    *MLD*

    Na MLD se mi nepovedlo správně sprovoznit skript a je tedy neotestováno.

4. Testování paketů protokolu ARP

   Cílem bylo otestovat, zdali síťový analyzátor správně zachytí pakety typu ARP na rozhraní `eth0`. Pro poslání paketů byl opět zvolen skript v jazyce Python verze 3, který na adresu `172.29.36.121` (ipv4 adresa eth0 rozhraní) poslal ARP dotaz (opět ze stejné adresy).

   Program byl pro testování spuštěn tímto příkazem:
    ```sh
    sudo ./ipk-sniffer -i eth0 --arp
    ```
    Výpis programu:
      ```sh
      timestamp: 2024-04-22T19:15:57.366+02:00
      src MAC: 00:00:00:00:00:00
      dst MAC: ff:ff:ff:ff:ff:ff
      frame length: 42
      packet type: ARP
      sender protocol address: 172.29.36.121
      target protocol address: 172.29.36.121
      ARP operation: REQUEST

      0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 06 00 01  ........ ........
      0x0010: 08 00 06 04 00 01 00 00 00 00 00 00 ac 1d 24 79  ........ ......$y
      0x0020: 00 00 00 00 00 00 ac 1d 24 79                    ........ $y
      ```

   Screenshot odchyceného paketu z programu Wireshark:
   [Paket zachycený ve Wiresharku](image/Wireshark_ARP.jpg)

    Paket ve Wiresharku se opět shoduje s výpisem síťového analyzátoru, jelikož při ARP dotazu není známá MAC adresa je poslán jako broadcast, tedy lze vidět např. pro něj specifickou adresu, rovněž je u ARP správně rozpoznán a vytisknut typ (ve Wiresharku je vidět i jako "Who has 172.29.36.121").

5. Testování paketů protokolu IGMP
   
   Cílem bylo otestovat, zdali síťový analyzátor správně zachytí pakety typu IGMO na rozhraní `lo`. Pro poslání paketů byl opět zvolen skript v jazyce Python verze 3, který na ipv4 adresu localhost poslal IGMP paket typu `IGMPv2 membership report` se skupinovou adresou `224.0.0.1`, což je adresa pro multicast.

   Program byl pro testování spuštěn tímto příkazem:
    ```sh
    sudo ./ipk-sniffer -i lo --igmp
    ```
    Výpis programu:
      ```
      timestamp: 2024-04-22T19:28:56.235+02:00
      src MAC: 00:00:00:00:00:00
      dst MAC: 00:00:00:00:00:00
      frame length: 42
      src IP: 127.0.0.1
      dst IP: 127.0.0.1
      packet type: IGMP
      igmp type: membership report version 2
      igmp routing code: 0
      igmp group address: 224.0.0.1

      0x0000: 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00  ........ ......E.
      0x0010: 00 1c 16 9c 40 00 40 02 26 42 7f 00 00 01 7f 00  ....@.@. &B......
      0x0020: 00 01 16 00 fe 09 e0 00 00 01                    ........ ..
      ```

   Screenshot odchyceného paketu z programu Wireshark:
   [Paket zachycený ve Wiresharku](image/Wireshark_IGMP.jpg)

    Paket ve Wiresharku má tentokrát červené políčko IGMP, jelikož skript má chybný výpočet kontrolní sumy (nedůležité v kontextu odchycení správného typu, jelikož nám nejde o validitu těchto dat). Kromě této maličkosti se ovšem výstupy opět shodují.


## Možná vylepšení
Síťový analyzátor není dokonalý a obsahuje několik věcí, které by mohly být v budocnu vylepšeny, mezi ně patří například:

* Síťový analyzátor umí pracovat pouze s ethernetovými rámci
* Výpisy by mohly být barevně laděné (lepší přehlednost mezi různými informacemi)
* K výpisům by mohl být přidán celkový počet zpracovaných paketů
* Otestování MLD paketů

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