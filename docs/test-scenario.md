# Testni scenarij – ocena zaupanja enega akterja (DON, 3 oraklji)

Osnovni cilj: ponovljivo preveriti, kako se trije oraklji (vezani na Pfizer, Moderna, DHL) izračunajo zaupanja do ene tarče in kako EMA dobi končno odločitev. Oraklji ostanejo isti, dodali smo več akterjev v ontologijo, da je primer realnejši.

## Udeleženci
- **EMA** – kliče `requestTrustReport`, preverja oraklje, predstavlja avtoriteto.
- **Oraklji** – `Pfizer` (hibrid), `Moderna` (VC-only), `DHL` (telemetry). Mapa naslovi → evaluatorji je že v `docker-compose.yml` (`NODE_EVALUATOR_MAP`).
- **Tarča** – `http://example.org/trust#MedLogix` (distributer). Alternativne tarče: `HealthChain` (transporter, pozitivnen), `SkyFreight` (transporter, negativni test), `BioPharm` (proizvajalec, delno pozitiven), `CanaryLabs` (proizvajalec, negativni VC).

## Testni podatki (fixture)
- Nova datoteka `data/fixtures/test-actors.ttl` doda 6 akterjev z metrikami (`hasDeliveryPunctuality`, `hasTempViolationRate`, `hasRecallRate`, `hasLicense`, `hasGDPVC`, `hasAuditScore`, `hasTempDeviationScore`, `hasPrescriptionComplianceRate`).
- Naloži v Fuseki (po uvozu osnovnega `ontologies/pharma-trust.owl`); predpostavka: `PHARM_NS`/`NAMESPACE` sta `http://example.org/trust#`.
  ```bash
  # 1) uvoz osnovne ontologije (če še ni v datasetu)
  curl -u "$FUSEKI_USER:$FUSEKI_PASS" -X POST \
    -H "Content-Type: application/rdf+xml" \
    "$FUSEKI_BASE_URL/$FUSEKI_DATASET/data" \
    --data-binary @ontologies/pharma-trust.owl

  # 2) uvoz dodatnih akterjev
  curl -u "$FUSEKI_USER:$FUSEKI_PASS" -X POST \
    -H "Content-Type: text/turtle" \
    "$FUSEKI_BASE_URL/$FUSEKI_DATASET/data" \
    --data-binary @data/fixtures/test-actors.ttl
  ```

## Hiter potek (TL;DR)
1. `. .venv/bin/activate && pip install -r requirements.txt` (enkratno).
2. `make env` in v `.env` nastavi `PHARM_NS=http://example.org/trust#` ter `NAMESPACE=http://example.org/trust#`.
3. Zaženi podporne servise: `docker compose up -d fuseki anvil`.
4. Uvozi bazno ontologijo + fixture (ukaza zgoraj).
5. Deployaj pogodbo: `make deploy` (lovi `CONTRACT_ADDRESS` v `.env`).
6. Zaženi DON: `make don-up` (agregator + 3 oraklji).
7. Zahtevaj oceno za tarčo (privzeto MedLogix):  
   `make request ARGS="http://example.org/trust#MedLogix"`
8. Rezultate preglej v logih (docker) ali on-chain (`cast call getTrustMetrics` iz `.env`).

## Pričakovana obnašanja (primeri)
- **MedLogix (Distributor)** – Pfizer = PASS (licenca + GDP VC), Moderna = PASS (licenca + GDP VC), DHL = FAIL (zahteva `hasDeliveryPunctuality >= 0.95`, imamo 0.93) → EMA vidi mešano sliko; razloži divergenčno politiko.
- **HealthChain (Transporter)** – Pfizer PASS, Moderna PASS (`hasRecallRate` 0.015 <= 0.02), DHL ne ocenjuje transporterjev → večina pozitivna.
- **SkyFreight (Transporter)** – Pfizer FAIL (0.90 < 0.99), Moderna FAIL (`hasRecallRate` 0.035 > 0.02) → EMA dobi zavrnitev.
- **BioPharm (Manufacturer)** – Pfizer PASS (0.90 audit), Moderna FAIL (zahteva ≥0.92), DHL PASS (`hasTempDeviationScore` 0.08 ≤ 0.10) → mešana mnenja.
- **CanaryLabs (Manufacturer)** – Pfizer FAIL (audit 0.81 < 0.90), Moderna FAIL, DHL FAIL (brez GDP VC) → skupni FAIL.

## Detajlni koraki (ponovljiv e2e)
1. **Priprava okolja**  
   - `. .venv/bin/activate` in `pip install -r requirements.txt`.  
   - `.env`: `PHARM_NS=http://example.org/trust#`, `NAMESPACE=http://example.org/trust#`, `FUSEKI_BASE_URL=http://localhost:3030`, `FUSEKI_DATASET=trustkb`, `FUSEKI_USER=admin`, `FUSEKI_PASS=admin123`.
2. **Start lokalnih servisov**  
   - `docker compose up -d fuseki anvil` (čakaš ~5s).  
   - (opcijsko) `make chain` če želiš lokalno anvil instanco ločeno.
3. **Seed podatkov**  
   - Uvozi `ontologies/pharma-trust.owl` in `data/fixtures/test-actors.ttl` (glej zgoraj).  
   - Potrdi: `. .venv/bin/activate && python -m src.trustkb.cli list-manufacturers`.
4. **Veriga + DON**  
   - `make deploy` → zapis `CONTRACT_ADDRESS` v `.env`.  
   - `make don-up` → agregator + 3 oraklji; preveri `docker compose logs -f aggregator oracle_node oracle_moderna oracle_dhl`.
5. **Zahteva EMA**  
   - Primer: `make request ARGS="http://example.org/trust#MedLogix"` (EMA lahko zamenja tarčo).  
   - Skripta poll-a `getTrustMetrics` do `TrustOracleFulfilled`. Submissions vsako orakelj se zapišejo v `oracleSubmissions`.
6. **Branje rezultatov**  
   - Povzetek: `cast call $CONTRACT_ADDRESS "getTrustMetrics(bytes32)((bool,uint256,uint256,uint64,bytes32,bytes32))" $(cast keccak "http://example.org/trust#MedLogix")`.  
   - Per-oracle: `cast call ... "oracleSubmissions(bytes32,bytes32)((bool,uint256,uint256,uint64,bytes32,bytes32,address,bytes32))" $(cast keccak "http://example.org/trust#Pfizer") $(cast keccak "http://example.org/trust#MedLogix")`.
7. **Negativni testi**  
   - Poizkusi z `SkyFreight` in preveri, da EMA dobi zavrnitev.  
   - Odstrani `hasGDPVC` iz `test-actors.ttl` za izbranega akterja in ponovno uvoz za prikaz VC-blokade.

## Čiščenje
- Ustavi DON: `make don-down`.  
- (opcijsko) počisti state/loge: `make clean`.

Ta scenarij ostane lokalno ponovljiv: isti 3 oraklji, deterministični fixture, tarčo lahko menjaš z `ARGS`, EMA dobi jasen signal, kateri orakelj je odločitev dal in zakaj.
