# Tietoturvallinen P2P-viestisovellus (LAN + WAN + Proxy + UPnP)

Tämä projekti on päästä päähän salattu viestisovellus, joka toimii:

- **LAN-verkossa** suoran yhteyden avulla  
- **WAN/Internetin yli** välipalvelimen (**relay_server**) kautta  
- **Mahdollisuuksien mukaan suoraan WANista** automaattisen **UPnP-portinavauksen** avulla

Kaikki viestit salataan **NaCl (PyNaCl)** -kirjastolla. Välipalvelin ei näe viestien sisältöä, vaan välittää pelkkää salattua dataa.

---

## 1. Projektin rakenne

- `secure_chat_gui.py`  
  Pääsovellus (GUI), jonka käyttäjä avaa työasemalla.

- `relay_server.py`  
  Kevyt välipalvelin (proxy), jota voidaan ajaa:
  - LAN-verkossa testaukseen
  - tai mieluiten **VPS:llä** / julkisella palvelimella WAN-yhteyksiä varten.

- `id_ed25519.key`  
  Laitteen pysyvä identiteettiavain (luodaan automaattisesti).  
  Tätä **ei pidä jakaa** muille.  

---

## 2. Ominaisuudet

- Päästä päähän salattu viestikanava (NaCl / PyNaCl)
- Ed25519-identiteetti + sormenjälki (SHA-256)
- Symmetrinen kättely: molemmat osapuolet todentavat toisensa
- Viestikohtaiset luku-kuittaukset (”viesti luettu”)
- **LAN-suora yhteys**
- **WAN-yhteys**:
  - varmaksi **relay_server.py**-välipalvelimen kautta
  - mahdollisuuksien mukaan **suora WAN** automaattisen UPnP-portinavauksen avulla
- Yksinkertainen mutta selkeä **Tkinter GUI**, jossa on vihjetekstejä ja ohjeita

---

## 3. Vaatimukset

- **Python 3.11+** (suositeltu)
- Seuraavat kirjastot:

```powershell
python -m pip install pynacl miniupnpc
