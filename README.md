# 🏥 Gematik TI Test-Tools

Tools zum Testen der Verbindung zu Gematik Telematikinfrastruktur (TI) Diensten:
- **ePA 3.x** (elektronische Patientenakte "ePA für alle")
- **E-Rezept** (elektronisches Rezept)

Verfügbar als:
- **PowerShell-Skripte** - Standalone-Skripte ohne Kompilierung
- **C# Konsolen-Anwendung** - Plattformübergreifende .NET 8.0 Anwendung

> ⚠️ **HINWEIS**: Diese Tools dienen Testzwecken und der Entwicklung. Für den produktiven Einsatz sind weitere Sicherheitsmaßnahmen erforderlich.

## 📋 Inhaltsverzeichnis

- [Voraussetzungen](#voraussetzungen)
- [Installation](#installation)
- [PowerShell-Skripte](#powershell-skripte)
  - [ePA Testskript](#epa-testskript-epa_testps1)
  - [E-Rezept Testskript](#e-rezept-testskript-erezept_testps1)
- [C# Konsolen-Anwendung](#c-konsolen-anwendung)
- [Konfiguration](#konfiguration)
- [Authentifizierung](#authentifizierung)
- [Technische Details](#technische-details)
- [Referenzen](#referenzen)
- [Lizenz](#lizenz)

## Voraussetzungen

### Für PowerShell-Skripte
- **Windows PowerShell 5.1** oder **PowerShell 7+**
- **.NET Framework 4.0+** oder **.NET 6.0+**

### Für C# Konsolen-Anwendung
- **.NET 8.0 SDK** oder höher
- Plattformübergreifend (Windows, Linux, macOS)

### Allgemein
- Zugang zur Gematik Telematikinfrastruktur (TI)
- Registrierte OIDC Client-ID bei einem sektoralen IDP

### Für Versicherte (Patienten)
- GesundheitsID (Authentifizierung über die App Ihrer Krankenkasse)
- Oder: elektronische Gesundheitskarte (eGK) mit PIN

### Für Leistungserbringer (Ärzte, Apotheken)
- SMC-B Karte (Institutionskarte)
- Konnektor-Zugang

## Installation

### 1. Repository klonen

```powershell
git clone https://github.com/winklersoft/eRezept.git
cd eRezept
```

### 2. Abhängigkeiten installieren

Die Skripte benötigen externe .NET-Bibliotheken für Kryptografie:

```powershell
# In den lib-Ordner wechseln
cd lib

# NuGet herunterladen (falls nicht vorhanden)
Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile "nuget.exe"

# Bibliotheken installieren
.\nuget.exe install PeterO.Cbor -Version 4.5.3 -OutputDirectory .
.\nuget.exe install BouncyCastle.Cryptography -Version 2.4.0 -OutputDirectory .

cd ..
```

### 3. C# Anwendung kompilieren (optional)

```powershell
cd src/GematikTI
dotnet build
```

### 4. Konfiguration anpassen

**PowerShell:** Öffnen Sie das gewünschte Skript und füllen Sie den Abschnitt **PFLICHT-KONFIGURATION** aus.

**C#:** Bearbeiten Sie die Datei `src/GematikTI/config.json`.

## PowerShell-Skripte

### ePA Testskript (`epa_test.ps1`)

Testet die Verbindung zur elektronischen Patientenakte (ePA 3.x "ePA für alle").

**Funktionen:**
- ✅ VAU-Protokoll Handshake (Nachrichten 1-4)
- ✅ Post-Quantum-sichere Verschlüsselung (Kyber768/ML-KEM-768)
- ✅ ECDH P-256 + Kyber768 Hybrid-Schlüsselaustausch
- ✅ AES/GCM Verschlüsselung für Nutzdaten
- ✅ OIDC/PKCE Authentifizierung
- ✅ FHIR R4 API Zugriff

**Verwendung:**
```powershell
.\epa_test.ps1
```

### E-Rezept Testskript (`eRezept_test.ps1`)

Prüft ob E-Rezepte für einen Versicherten vorliegen.

**Funktionen:**
- ✅ IDP Discovery (zentral oder sektoral)
- ✅ OIDC/PKCE Authentifizierung
- ✅ E-Rezept Task-Abfrage über FHIR API
- ✅ Formatierte Anzeige der Rezepte
- ✅ Export als JSON

**Verwendung:**
```powershell
.\eRezept_test.ps1
```

## C# Konsolen-Anwendung

Die C# Anwendung (`src/GematikTI/`) bietet die gleiche Funktionalität wie die PowerShell-Skripte in einer plattformübergreifenden .NET 8.0 Anwendung.

### Kompilieren

```powershell
cd src/GematikTI
dotnet build
```

### Verwendung

```powershell
# Hilfe anzeigen
dotnet run -- --help

# ePA testen
dotnet run -- epa -c config.json

# E-Rezept prüfen
dotnet run -- erezept -c config.json

# Mit eigener Konfigurationsdatei
dotnet run -- epa -c /pfad/zu/meine-config.json
```

### Konfigurationsdatei (JSON)

Die C# Anwendung verwendet eine JSON-Konfigurationsdatei:

```json
{
  "Umgebung": "RU",
  "EPA": {
    "AktensystemBaseUrl": "https://epa.ibm-gesundheit.de"
  },
  "ERezept": {
    "FdBaseUrl": "https://erp-ref.zentral.erp.splitdns.ti-dienste.de",
    "IdpBaseUrl": "https://idp-ref.zentral.idp.splitdns.ti-dienste.de"
  },
  "Authentifizierung": {
    "Methode": "GesundheitsID",
    "OidcClientId": "IHRE_CLIENT_ID",
    "OidcRedirectUri": "http://localhost:8080/callback",
    "SektoralerIdpDiscoveryUrl": "https://idp.example.de/.well-known/openid-configuration"
  },
  "Versicherter": {
    "KVNR": "X123456789"
  },
  "Optionen": {
    "VerboseLogging": false,
    "HttpTimeoutSeconds": 30
  }
}
```

### Projektstruktur C#

```
src/GematikTI/
├── GematikTI.csproj           # Projektdatei
├── Program.cs                 # Einstiegspunkt + CLI
├── config.json                # Beispiel-Konfiguration
├── Configuration/
│   └── GematikConfig.cs       # Konfigurationsklassen
├── Logging/
│   └── Logger.cs              # Konsolenausgabe
├── Crypto/
│   ├── PkceChallenge.cs       # PKCE-Implementierung
│   └── VauCrypto.cs           # Kyber768, ECDH, AES/GCM, HKDF
├── Auth/
│   └── OidcAuthService.cs     # OIDC-Authentifizierung
├── Epa/
│   ├── VauProtocolClient.cs   # VAU-Protokoll
│   └── EpaClient.cs           # ePA-Client
└── ERezept/
    └── ERezeptClient.cs       # E-Rezept-Client
```

## Konfiguration

### ePA Konfiguration

| Parameter | Beschreibung | Beispiel |
|-----------|--------------|----------|
| `Umgebung` | RU/TU/PU | `"RU"` |
| `AktensystemBaseUrl` | URL des Aktenanbieters | `"https://epa.ibm-gesundheit.de"` |
| `SektoralerIdpDiscoveryUrl` | OIDC Discovery URL | `"https://idp.tk.de/.well-known/openid-configuration"` |
| `OidcClientId` | Registrierte Client-ID | `"meine-app-id"` |
| `KVNR` | Krankenversichertennummer | `"X123456789"` |

### E-Rezept Konfiguration

| Parameter | Beschreibung | Beispiel |
|-----------|--------------|----------|
| `Umgebung` | RU/TU/PU | `"RU"` |
| `ERezeptFdBaseUrl` | URL des E-Rezept-Fachdienstes | `"https://erp-ref.zentral.erp.splitdns.ti-dienste.de"` |
| `IdpBaseUrl` | URL des TI-IDP | `"https://idp-ref.zentral.idp.splitdns.ti-dienste.de"` |
| `OidcClientId` | Registrierte Client-ID | `"meine-app-id"` |
| `KVNR` | Krankenversichertennummer | `"X123456789"` |
| `AuthMethode` | Authentifizierungsmethode | `"GesundheitsID"` oder `"eGK"` |

### Umgebungen

| Umgebung | Beschreibung | E-Rezept URL | IDP URL |
|----------|--------------|--------------|---------|
| **RU** | Referenzumgebung (Test) | `erp-ref.zentral.erp.splitdns.ti-dienste.de` | `idp-ref.zentral.idp.splitdns.ti-dienste.de` |
| **TU** | Testumgebung | `erp-test.zentral.erp.splitdns.ti-dienste.de` | `idp-test.zentral.idp.splitdns.ti-dienste.de` |
| **PU** | Produktivumgebung | `erp.zentral.erp.splitdns.ti-dienste.de` | `idp.zentral.idp.splitdns.ti-dienste.de` |

## Authentifizierung

### GesundheitsID (empfohlen für Versicherte)

1. Das Skript generiert eine Authorization-URL
2. Öffnen Sie die URL im Browser
3. Authentifizieren Sie sich mit Ihrer Krankenkassen-App
4. Kopieren Sie den `code`-Parameter aus der Redirect-URL
5. Geben Sie den Code im Skript ein

### eGK (erfordert Konnektor)

Die Authentifizierung per elektronischer Gesundheitskarte erfordert:
- Einen konfigurierten Konnektor
- Ein Kartenterminal mit eingelegter eGK
- Die PIN der eGK

## Technische Details

### VAU-Protokoll (ePA)

Das VAU-Protokoll (Vertrauenswürdige Ausführungsumgebung) gemäß `gemSpec_Krypt` Kapitel 7:

```
Client                                    VAU-Instanz
   |                                           |
   |  -------- Nachricht 1 (M1) ----------->  |  ECDH_PK + Kyber768_PK
   |  <------- Nachricht 2 (M2) -----------   |  KEM Ciphertexts + Zertifikat
   |  -------- Nachricht 3 (M3) ----------->  |  KEM Encapsulate + Bestätigung
   |  <------- Nachricht 4 (M4) -----------   |  Schlüsselbestätigung
   |                                           |
   |  ======= Verschlüsselter Kanal ========  |  AES/GCM mit K2-Schlüsseln
```

### Verwendete Kryptografie

| Algorithmus | Verwendung | Spezifikation |
|-------------|------------|---------------|
| ECDH P-256 | Schlüsselaustausch | NIST FIPS 186-4 |
| Kyber768/ML-KEM-768 | Post-Quantum KEM | NIST FIPS 203 |
| AES-256-GCM | Symmetrische Verschlüsselung | NIST SP 800-38D |
| SHA-256 | Hashing | NIST FIPS 180-4 |
| HKDF | Schlüsselableitung | RFC 5869 |

### Bibliotheken

| Bibliothek | Version | Verwendung |
|------------|---------|------------|
| PeterO.Cbor | 4.5.3 | CBOR-Serialisierung (RFC 8949) |
| BouncyCastle.Cryptography | 2.4.0 | Kyber768, ECDH, AES/GCM |

## Projektstruktur

```
eRezept/
├── epa_test.ps1               # ePA 3.x Testskript (PowerShell)
├── eRezept_test.ps1           # E-Rezept Testskript (PowerShell)
├── README.md                  # Diese Datei
├── LICENSE                    # MIT Lizenz
├── .gitignore                 # Git Ignore-Datei
├── lib/                       # Externe Bibliotheken (PowerShell)
│   ├── PeterO.Cbor.4.5.3/
│   ├── PeterO.Numbers.1.8.2/
│   └── BouncyCastle.Cryptography.2.4.0/
└── src/
    └── GematikTI/             # C# Konsolen-Anwendung
        ├── GematikTI.csproj
        ├── Program.cs
        ├── config.json
        ├── Configuration/
        ├── Logging/
        ├── Crypto/
        ├── Auth/
        ├── Epa/
        └── ERezept/
```

## Referenzen

### Gematik Spezifikationen

- [gemSpec_Krypt](https://fachportal.gematik.de/spezifikationen/online-produktivbetrieb/konzepte-und-spezifikationen) - Kryptografische Vorgaben
- [gemSpec_FD_eRp](https://fachportal.gematik.de/spezifikationen/online-produktivbetrieb/konzepte-und-spezifikationen) - E-Rezept Fachdienst
- [gemSpec_ePA_FdV](https://fachportal.gematik.de/spezifikationen/online-produktivbetrieb/konzepte-und-spezifikationen) - ePA Frontend des Versicherten
- [gemSpec_IDP_Dienst](https://fachportal.gematik.de/spezifikationen/online-produktivbetrieb/konzepte-und-spezifikationen) - Identity Provider

### Standards

- [FHIR R4](https://hl7.org/fhir/R4/) - HL7 FHIR Release 4
- [RFC 7636](https://tools.ietf.org/html/rfc7636) - PKCE for OAuth 2.0
- [RFC 8949](https://tools.ietf.org/html/rfc8949) - CBOR
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HKDF

### Gematik Portale

- [Gematik Fachportal](https://fachportal.gematik.de/)
- [Gematik GitHub](https://github.com/gematik)
- [API-Dokumentation E-Rezept](https://github.com/gematik/api-erp)

## Fehlerbehebung

### "Bibliotheken nicht gefunden"

Stellen Sie sicher, dass die NuGet-Pakete korrekt installiert sind:

```powershell
cd lib
.\nuget.exe install PeterO.Cbor -Version 4.5.3 -OutputDirectory .
.\nuget.exe install BouncyCastle.Cryptography -Version 2.4.0 -OutputDirectory .
```

### "KVNR hat ungültiges Format"

Die KVNR muss aus einem Großbuchstaben gefolgt von 9 Ziffern bestehen:
- ✅ Korrekt: `X123456789`
- ❌ Falsch: `123456789X`, `x123456789`

### "Timeout bei IDP Discovery"

- Prüfen Sie Ihre Internetverbindung
- Stellen Sie sicher, dass Sie Zugang zur TI haben
- Versuchen Sie es mit einer anderen Umgebung (RU/TU)

## Lizenz

MIT License - siehe [LICENSE](LICENSE) Datei.

## Autor

WinklerSoft - [GitHub](https://github.com/winklersoft)

---

**Haftungsausschluss**: Diese Software wird "wie besehen" ohne Gewährleistung bereitgestellt. Die Nutzung erfolgt auf eigene Gefahr. Für den Einsatz im Produktivbetrieb mit echten Patientendaten sind zusätzliche Sicherheitsmaßnahmen und Zertifizierungen erforderlich.
