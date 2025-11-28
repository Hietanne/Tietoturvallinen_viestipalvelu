# Tietoturvallinen P2P-viestisovellus  
*(LAN + WAN + Proxy + UPnP + Ratchet-salaus)*

Tämä projekti on päästä päähän salattu viestisovellus, joka toimii:

- **LAN-verkossa** suoran yhteyden avulla  
- **WAN/Internetin yli** välipalvelimen (**relay_server**) kautta  
- **Mahdollisuuksien mukaan suoraan WANista** automaattisen **UPnP-portinavauksen** avulla

Kaikki viestit salataan **NaCl (PyNaCl)** -kirjastolla, ja lisäksi jokaiselle viestille käytetään **erillistä avainta (ratchet)**.  
Välipalvelin ei näe viestien sisältöä, vaan välittää pelkkää salattua dataa.

---

## 1. Projektin rakenne

- `secure_chat_gui.py`  
  Pääsovellus (Tkinter-GUI), jonka käyttäjä avaa työasemalla.  
  - LAN-suora yhteys  
  - WAN-yhteys välipalvelimen kautta  
  - UPnP-yritys WAN-suoraan porttiin  
  - ratchet-salaus per viesti  
  - luku-kuittaukset ja identiteettien sormenjäljet

- `relay_server.py`  
  Kevyt välipalvelin (proxy), jota voidaan ajaa:
  - LAN-verkossa testaukseen
  - tai mieluiten **VPS:llä** / julkisella palvelimella WAN-yhteyksiä varten.  
  Relay ei pura salausta – se vain välittää kehyksiä.

- `id_ed25519.key`  
  Laitteen pysyvä **identiteettiavain** (Ed25519), luodaan automaattisesti.  
  Tätä **ei pidä jakaa** muille.

- `known_peers.json`  
  Tiedosto, johon sovellus tallentaa **tunnetut vastapuolten sormenjäljet** eri konteksteissa:
  - suora IP/portti (LAN/WAN)
  - proxy-huonekoodi  
  Käytetään **identity pinning** -tyyliin: jos samaan huoneeseen/IP:hen tulee myöhemmin eri sormenjälki, käyttöliittymä varoittaa.

---

## 2. Ominaisuudet

Turvaominaisuudet:

- ✅ **Päästä päähän salattu viestikanava** (NaCl / PyNaCl)
- ✅ **Ed25519-identiteetti + sormenjälki (SHA-256)**
- ✅ **Symmetrinen kättely**: molemmat osapuolet todentavat toisensa
- ✅ **Ratchet-salaus (per viesti uusi avain)**  
  → jos yksi avain vuotaa, menneitä ja tulevia viestejä ei voi purkaa (forward secrecy istunnon sisällä)
- ✅ **Replay-suoja** (seq-numero per viesti, ei hyväksytä kaksoistoistoja tai vanhoja viestejä)
- ✅ **Peruspadding** viestiin → ulkopuolinen ei näe tarkkaa viestin pituutta niin helposti
- ✅ **Identity pinning (known_peers.json)**  
  → varoitus, jos samaan huoneeseen/IP:hen ilmestyy myöhemmin eri identiteetti/sormenjälki
- ✅ Viestikohtaiset **luku-kuittaukset** (”viesti luettu”)

Yhteysominaisuudet:

- **LAN-suora yhteys**
- **WAN-yhteys**:
  - varmalla tavalla **relay_server.py**-välipalvelimen kautta
  - mahdollisuuksien mukaan **suora WAN** automaattisen UPnP-portinavauksen avulla
- Yksinkertainen mutta selkeä **Tkinter GUI**, jossa on vihjetekstejä ja ohjeita

---

## 3. Vaatimukset

- **Python 3.11+** (suositeltu)
- Seuraavat kirjastot:

```powershell
python -m pip install pynacl miniupnpc
