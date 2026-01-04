# =============================================================================
# Konfiguration fuer RISE Testumgebung (Referenzumgebung RU)
# Verwendung mit Gematik Testsuite
# =============================================================================
#
# Diese Datei vor der Verwendung in den Skript-Ordner kopieren und umbenennen.
# Oder laden Sie die Konfiguration mit:
#   . .\config.rise-ru.ps1
#
# =============================================================================

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    EPA-KONFIGURATION (RISE RU)                            ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

$Config = @{
    # Umgebung: RU = Referenzumgebung (Gematik Testsuite)
    Umgebung = "RU"
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ AKTENSYSTEM-KONFIGURATION (RISE/IBM)                               │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # RISE ePA Aktensystem - Referenzumgebung
    # Titus ist die Gematik Testumgebung fuer TI-Anwendungen
    AktensystemBaseUrl = "https://kon-instanz1.titus.ti-dienste.de"
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ IDP-KONFIGURATION (Gematik zentraler IDP)                          │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # Discovery-Endpunkt des zentralen Gematik IDP (Referenzumgebung)
    SektoralerIdpDiscoveryUrl = "https://idp-ref.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration"
    
    # Client-ID aus der Gematik Testsuite
    # WICHTIG: Muss bei Gematik/Testsuite registriert sein!
    OidcClientId = "gematikTestsuite"
    
    # Redirect-URI (muss beim IDP registriert sein)
    OidcRedirectUri = "http://localhost:8080/callback"
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ VERSICHERTEN-DATEN (Gematik Test-KVNR)                             │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # Test-KVNR aus der Gematik Testsuite
    # Verfuegbare Test-KVNRs siehe Gematik Testsuite Dokumentation
    Kvnr = "X110411675"
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ TLS-KONFIGURATION                                                  │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # In der Testsuite wird kein mTLS benoetigt
    UseMutualTls = $false
    ClientCertPfxPath = ""
    ClientCertPassword = ""
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    OPTIONALE KONFIGURATION                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

$OptionalConfig = @{
    # Timeout fuer HTTP-Requests (hoeher fuer Testumgebung)
    HttpTimeoutSeconds = 60
    
    # Debug-Ausgaben aktivieren
    VerboseLogging = $true
    
    # VAU-Protokoll Trace (nur fuer Entwicklung/Test!)
    EnableVauTracing = $true
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    E-REZEPT-KONFIGURATION (Gematik RU)                    ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

$ERezeptConfig = @{
    # Umgebung: RU = Referenzumgebung
    Umgebung = "RU"
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ E-REZEPT FACHDIENST                                                │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # E-Rezept Fachdienst - Referenzumgebung
    ERezeptFdBaseUrl = "https://erp-ref.zentral.erp.splitdns.ti-dienste.de"
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ IDP-KONFIGURATION                                                  │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # Zentraler Gematik IDP - Referenzumgebung
    IdpBaseUrl = "https://idp-ref.zentral.idp.splitdns.ti-dienste.de"
    
    # Sektoraler IDP Discovery (fuer GesundheitsID)
    SektoralerIdpDiscoveryUrl = "https://idp-ref.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration"
    
    # Client-ID (muss bei Gematik registriert sein)
    OidcClientId = "gematikTestsuite"
    
    # Redirect-URI
    OidcRedirectUri = "http://localhost:8080/callback"
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ VERSICHERTEN-DATEN                                                 │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # Test-KVNR
    Kvnr = "X110411675"
    
    # Authentifizierungsmethode: GesundheitsID oder eGK
    AuthMethode = "GesundheitsID"
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    HINWEISE ZUR VERWENDUNG                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
#
# 1. Diese Konfiguration ist fuer die Gematik Referenzumgebung (RU) gedacht
#
# 2. Die Client-ID "gematikTestsuite" ist ein Beispiel - verwenden Sie Ihre
#    eigene registrierte Client-ID
#
# 3. Test-KVNRs muessen zur Testsuite-Konfiguration passen
#
# 4. Fuer Produktivbetrieb (PU) muessen die URLs angepasst werden:
#    - E-Rezept: https://erp.zentral.erp.splitdns.ti-dienste.de
#    - IDP:      https://idp.zentral.idp.splitdns.ti-dienste.de
#
# 5. Gematik Testsuite Dokumentation:
#    https://github.com/gematik/app-Testsuite
#
# ═══════════════════════════════════════════════════════════════════════════
