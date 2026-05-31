# Home SOC Monitor

Backend demonstracyjny do pracy dyplomowej: analiza ryzyka wycieku danych z sieci domowej przez sprzet IoT.

Projekt symuluje prosty domowy SOC dla ruchu z urzadzen takich jak Smart TV, kamera IoT, PC, telefon i router. Aplikacja przyjmuje obserwacje ruchu sieciowego, zapisuje alerty do lokalnej H2 lub PostgreSQL w Dockerze i wystawia REST API do testow lokalnych oraz scenariuszy ataku.

## Co wykrywa

- nowe urzadzenie w sieci domowej,
- probe skanowania portow,
- podejrzane zapytania DNS, np. `webhook.site`, `ngrok`, `duckdns`,
- probe logowania do panelu routera,
- mozliwa eksfiltracje danych z urzadzen IoT do zewnetrznych adresow IP.

Kazdy alert ma typ, waznosc, wynik ryzyka, zrodlo, cel, port, protokol, liczbe wyslanych bajtow, pole `evidence` i mapowanie MITRE ATT&CK.

Przykladowe mapowania MITRE:

- `PORT_SCAN` -> Discovery / Network Service Discovery,
- `SUSPICIOUS_DNS` -> Command and Control / DNS,
- `POSSIBLE_DATA_EXFILTRATION` -> Exfiltration,
- `ROUTER_LOGIN_ATTEMPT` -> Credential Access.

## Uruchomienie w Dockerze

Na Linuxie wymagane sa:

- Docker Engine,
- Docker Compose v2, czyli komenda `docker compose`.

Pierwsze uruchomienie:

```bash
cp .env.example .env
# Ustaw w .env wlasne POSTGRES_PASSWORD.
docker compose up --build -d home-soc-monitor
```

Albo przez skrypt:

```bash
sh scripts/linux-start.sh
```

API bedzie dostepne na:

```text
http://localhost:8080
```

Dashboard SOC:

```text
http://localhost:8080
```

Stan aplikacji:

```bash
curl http://localhost:8080/actuator/health
```

## Scenariusz demo: atakujacy i IoT

Normalny ruch kamery IoT:

```bash
bash scripts/normal-traffic.sh
```

Ruch atakujacego / podejrzana eksfiltracja:

```bash
bash scripts/attacker-exfil.sh
```

Ten sam scenariusz jako osobny kontener:

```bash
docker compose --profile attack up --build
```

Albo:

```bash
sh scripts/linux-attack.sh
```

Normalny ruch IoT jako osobny kontener:

```bash
sh scripts/linux-normal-traffic.sh
```

Zatrzymanie srodowiska:

```bash
sh scripts/linux-stop.sh
```

Zasymuluj eksfiltracje ze Smart TV:

```bash
curl -X POST http://localhost:8080/api/simulate/smart-tv/exfil
```

Zasymuluj eksfiltracje z kamery IoT:

```bash
curl -X POST http://localhost:8080/api/simulate/camera/exfil
```

Pobierz ostatnie alerty:

```bash
curl http://localhost:8080/api/events
```

Pobierz raport SOC:

```bash
curl http://localhost:8080/api/report
```

Pobierz wykryte urzadzenia:

```bash
curl http://localhost:8080/api/devices
```

Wyczysc alerty:

```bash
curl -X DELETE http://localhost:8080/api/events
```

## Wlasna obserwacja ruchu

```bash
curl -X POST http://localhost:8080/api/observe \
  -H "Content-Type: application/json" \
  -d '{
    "sourceIp": "192.168.0.14",
    "sourceMac": "AA:BB:CC:05",
    "vendor": "IoT Camera",
    "destinationIp": "34.117.59.81",
    "destinationPort": 443,
    "protocol": "TLS",
    "bytesOut": 2500000,
    "dnsQuery": null
  }'
```

Przykladowy podzial do laboratorium:

- `localhost`: aplikacja SOC i API,
- `home-net`: symulowana siec domowa,
- `attacker`: kontener lub host wysylajacy zdarzenia do `/api/observe`,
- `iot-device`: skrypt generujacy normalny i podejrzany ruch IoT.

## Uruchomienie bez Dockera

Wymagania: Java 21 i Maven.

```bash
mvn test
mvn spring-boot:run
```

Domyslny profil `dev` zapisuje dane do lokalnego pliku H2 w katalogu `data/`.
Profil `docker` korzysta z PostgreSQL uruchamianego przez Docker Compose. Dane sa przechowywane w wolumenie `postgres-data`, wiec restart kontenera aplikacji nie usuwa historii alertow.

H2 console:

```text
http://localhost:8080/h2-console
```

JDBC URL:

```text
jdbc:h2:mem:homesoc
```
