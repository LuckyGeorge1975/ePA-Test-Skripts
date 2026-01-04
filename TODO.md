# TODO: Gematik TI Test-Tools in der RISE Testumgebung starten

Diese Anleitung beschreibt, wie die PowerShell-Skripte und das C# Programm in der Gematik RISE Testumgebung (Referenzumgebung RU) gestartet werden.

---

## Voraussetzungen

### Allgemein
- [ ] Zugang zur Gematik Telematikinfrastruktur (TI)
- [ ] Registrierte OIDC Client-ID bei Gematik
- [ ] Test-KVNR aus der Gematik Testsuite
- [ ] Netzwerkzugang zu den TI-Diensten (ggf. VPN)

### Für PowerShell-Skripte
- [ ] Windows PowerShell 5.1+ oder PowerShell 7+
- [ ] .NET Framework 4.0+ installiert
- [ ] NuGet-Pakete im `lib/` Ordner installiert:
  ```powershell
  cd lib
  .\nuget.exe install PeterO.Cbor -Version 4.5.3 -OutputDirectory .
  .\nuget.exe install BouncyCastle.Cryptography -Version 2.4.0 -OutputDirectory .
  ```

### Für C# Konsolen-Anwendung
- [ ] .NET 8.0 SDK installiert
- [ ] Projekt kompiliert:
  ```powershell
  cd src/GematikTI
  dotnet build
  ```

---

## Erforderliche Parameter

### Pflichtparameter

| Parameter | Beschreibung | Beispielwert |
|-----------|--------------|--------------|
| **OidcClientId** | Registrierte OIDC Client-ID | `gematikTestsuite` |
| **KVNR** | Krankenversichertennummer (10-stellig) | `X110411675` |
| **AktensystemBaseUrl** | URL des ePA-Aktensystems | `https://kon-instanz1.titus.ti-dienste.de` |
| **ERezeptFdBaseUrl** | URL des E-Rezept-Fachdienstes | `https://erp-ref.zentral.erp.splitdns.ti-dienste.de` |
| **IdpBaseUrl** | URL des zentralen IDP | `https://idp-ref.zentral.idp.splitdns.ti-dienste.de` |
| **SektoralerIdpDiscoveryUrl** | OIDC Discovery URL | `https://idp-ref.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration` |

### Optionale Parameter

| Parameter | Beschreibung | Standardwert |
|-----------|--------------|--------------|
| **OidcRedirectUri** | Callback-URL für OIDC | `http://localhost:8080/callback` |
| **HttpTimeoutSeconds** | HTTP-Timeout | `60` |
| **VerboseLogging** | Debug-Ausgaben | `true` |

---

## PowerShell-Skripte starten

### Option A: Konfigurationsdatei verwenden (empfohlen)

1. **Konfiguration laden:**
   ```powershell
   cd C:\Workspace\GitHub\winklersoft\eRezept
   . .\config.rise-ru.ps1
   ```

2. **Parameter anpassen (falls nötig):**
   ```powershell
   # Client-ID anpassen
   $Config.OidcClientId = "IHRE_CLIENT_ID"
   $ERezeptConfig.OidcClientId = "IHRE_CLIENT_ID"
   
   # Test-KVNR anpassen
   $Config.Kvnr = "X123456789"
   $ERezeptConfig.Kvnr = "X123456789"
   ```

3. **ePA-Test starten:**
   ```powershell
   .\epa_test.ps1
   ```

4. **E-Rezept-Test starten:**
   ```powershell
   .\eRezept_test.ps1
   ```

### Option B: Parameter direkt im Skript ändern

1. **epa_test.ps1 öffnen** und den `$Config`-Block anpassen (Zeilen 78-127)
2. **eRezept_test.ps1 öffnen** und den Konfigurationsblock anpassen

---

## C# Konsolen-Anwendung starten

### Option A: Mit vorkonfigurierter RISE-Konfiguration

```powershell
cd C:\Workspace\GitHub\winklersoft\eRezept\src\GematikTI

# ePA testen
dotnet run -- epa -c config.rise-ru.json

# E-Rezept prüfen
dotnet run -- erezept -c config.rise-ru.json
```

### Option B: Mit eigener Konfigurationsdatei

1. **Konfiguration kopieren und anpassen:**
   ```powershell
   Copy-Item config.rise-ru.json meine-config.json
   # meine-config.json bearbeiten
   ```

2. **Mit eigener Konfiguration starten:**
   ```powershell
   dotnet run -- epa -c meine-config.json
   dotnet run -- erezept -c meine-config.json
   ```

### Verfügbare Befehle

```powershell
# Hilfe anzeigen
dotnet run -- --help

# ePA-Hilfe
dotnet run -- epa --help

# E-Rezept-Hilfe
dotnet run -- erezept --help
```

### Befehlsübersicht

| Befehl | Beschreibung |
|--------|--------------|
| `epa` | Teste Verbindung zur elektronischen Patientenakte (ePA 3.x) |
| `erezept` | Prüfe E-Rezepte für einen Versicherten |

### Parameter für beide Befehle

| Parameter | Kurz | Beschreibung |
|-----------|------|--------------|
| `--config` | `-c` | Pfad zur JSON-Konfigurationsdatei |
| `--help` | `-h` | Hilfe anzeigen |

---

## Authentifizierungsablauf

Beide Tools verwenden OIDC/PKCE für die Authentifizierung:

1. **Tool startet** und zeigt eine Authorization-URL
2. **URL im Browser öffnen** und mit GesundheitsID authentifizieren
3. **Authorization Code kopieren** aus der Redirect-URL (`?code=...`)
4. **Code im Tool eingeben**
5. **Tokens werden abgerufen** und der Test läuft

---

## Testumgebungs-URLs (RISE RU)

| Dienst | URL |
|--------|-----|
| ePA Aktensystem (Titus) | `https://kon-instanz1.titus.ti-dienste.de` |
| E-Rezept Fachdienst | `https://erp-ref.zentral.erp.splitdns.ti-dienste.de` |
| Zentraler IDP | `https://idp-ref.zentral.idp.splitdns.ti-dienste.de` |
| IDP Discovery | `https://idp-ref.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration` |

---

## Fehlerbehebung

### "Bibliotheken nicht gefunden"
```powershell
cd lib
.\nuget.exe install PeterO.Cbor -Version 4.5.3 -OutputDirectory .
.\nuget.exe install BouncyCastle.Cryptography -Version 2.4.0 -OutputDirectory .
```

### "KVNR ungültig"
- Format prüfen: Großbuchstabe + 9 Ziffern (z.B. `X110411675`)
- Test-KVNR aus Gematik Testsuite verwenden

### "IDP Discovery fehlgeschlagen"
- Netzwerkverbindung zur TI prüfen
- VPN-Verbindung prüfen (falls erforderlich)
- URL auf Tippfehler prüfen

### "Client-ID nicht registriert"
- Client-ID bei Gematik/IDP-Betreiber registrieren
- Redirect-URI muss beim IDP hinterlegt sein

---

## Nächste Schritte

- [ ] Client-ID bei Gematik registrieren
- [ ] Test-KVNR von Gematik anfordern
- [ ] VPN/Netzwerkzugang zur TI einrichten
- [ ] Konfigurationsdateien mit eigenen Werten anpassen
- [ ] Tests durchführen und Ergebnisse dokumentieren

---

## Referenzen

- [Gematik API E-Rezept](https://github.com/gematik/api-erp)
- [Gematik IDP Server](https://github.com/gematik/ref-idp-server)
- [Gematik Fachportal](https://fachportal.gematik.de/)
- [gemSpec_Krypt](https://fachportal.gematik.de/spezifikationen) - VAU-Protokoll
- [gemSpec_FD_eRp](https://fachportal.gematik.de/spezifikationen) - E-Rezept Fachdienst
