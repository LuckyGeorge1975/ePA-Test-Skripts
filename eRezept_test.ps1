# =============================================================================
# gematik E-Rezept - PowerShell Testskript
# =============================================================================
# 
# WICHTIG: Dieses Skript implementiert die Abfrage von E-Rezepten gemaess
#          gemSpec_FD_eRp (E-Rezept-Fachdienst) und gemILF_PS_eRp.
#
# Referenzen:
#   - gemSpec_FD_eRp: Spezifikation E-Rezept-Fachdienst
#   - gemSpec_IDP_Dienst: Identity Provider Dienst
#   - gemILF_PS_eRp: Implementierungsleitfaden Primaersystem E-Rezept
#   - RFC 7636: PKCE fuer OAuth 2.0
#   - FHIR R4: HL7 FHIR Release 4
#
# Benoetigte Bibliotheken (im lib-Ordner):
#   - PeterO.Cbor: CBOR-Serialisierung (optional fuer VAU)
#   - BouncyCastle.Cryptography: Kryptografische Operationen
#
# =============================================================================

# ============================================================================
#                    BIBLIOTHEKEN LADEN
# ============================================================================

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibPath = Join-Path $ScriptRoot "lib"

# Pruefe ob Bibliotheken vorhanden sind (optional fuer dieses Skript)
$requiredLibs = @{
    "PeterO.Numbers" = @{
        Path = Join-Path $LibPath "PeterO.Numbers.1.8.2\lib\net40\Numbers.dll"
        Required = $false
    }
    "CBOR" = @{
        Path = Join-Path $LibPath "PeterO.Cbor.4.5.3\lib\net40\CBOR.dll"
        Required = $false
    }
    "BouncyCastle" = @{
        Path = Join-Path $LibPath "BouncyCastle.Cryptography.2.4.0\lib\netstandard2.0\BouncyCastle.Cryptography.dll"
        Required = $false
    }
}

foreach ($lib in $requiredLibs.GetEnumerator()) {
    if (Test-Path $lib.Value.Path) {
        try {
            Add-Type -Path $lib.Value.Path -ErrorAction Stop
            Write-Host "[OK] $($lib.Key) geladen" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -like "*already loaded*" -or $_.Exception.Message -like "*bereits geladen*") {
                Write-Host "[OK] $($lib.Key) bereits geladen" -ForegroundColor Green
            } else {
                Write-Host "[WARN] $($lib.Key) Ladefehler: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } elseif ($lib.Value.Required) {
        Write-Host "[FEHLER] $($lib.Key) nicht gefunden (erforderlich): $($lib.Value.Path)" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "[INFO] $($lib.Key) nicht gefunden (optional): $($lib.Value.Path)" -ForegroundColor Gray
    }
}

# ============================================================================
#                    PFLICHT-KONFIGURATION (ANPASSEN!)
# ============================================================================

# --- E-Rezept-Fachdienst Endpunkte ---
# Hinweis: Es gibt nur einen zentralen E-Rezept-Fachdienst der gematik

$Config = @{
    # -------------------------------------------------------------------------
    # UMGEBUNG: "RU" (Referenzumgebung/Test), "TU" (Testumgebung), "PU" (Produktivumgebung)
    # -------------------------------------------------------------------------
    Umgebung = "RU"                                              # <-- HIER EINTRAGEN
    
    # -------------------------------------------------------------------------
    # E-REZEPT-FACHDIENST URLs (je nach Umgebung)
    # -------------------------------------------------------------------------
    # Referenzumgebung (RU):
    #   FD:  https://erp-ref.zentral.erp.splitdns.ti-dienste.de
    #   IDP: https://idp-ref.zentral.idp.splitdns.ti-dienste.de
    # 
    # Testumgebung (TU):
    #   FD:  https://erp-test.zentral.erp.splitdns.ti-dienste.de
    #   IDP: https://idp-test.zentral.idp.splitdns.ti-dienste.de
    #
    # Produktivumgebung (PU):
    #   FD:  https://erp.zentral.erp.splitdns.ti-dienste.de
    #   IDP: https://idp.zentral.idp.splitdns.ti-dienste.de
    # -------------------------------------------------------------------------
    
    ERezeptFdBaseUrl = ""                                        # <-- HIER EINTRAGEN
    # Beispiel RU: "https://erp-ref.zentral.erp.splitdns.ti-dienste.de"
    
    IdpBaseUrl = ""                                              # <-- HIER EINTRAGEN
    # Beispiel RU: "https://idp-ref.zentral.idp.splitdns.ti-dienste.de"
    
    # -------------------------------------------------------------------------
    # AUTHENTIFIZIERUNG
    # -------------------------------------------------------------------------
    # Fuer E-Rezept wird die Authentifizierung ueber den zentralen IDP der TI
    # durchgefuehrt. Versicherte authentifizieren sich mit ihrer eGK oder
    # der GesundheitsID (ueber sektoralen IDP).
    # -------------------------------------------------------------------------
    
    # OIDC Client-ID (vom IDP-Anbieter erhalten)
    OidcClientId = ""                                            # <-- HIER EINTRAGEN
    
    # Redirect-URI fuer den OIDC-Flow (muss beim IDP registriert sein)
    OidcRedirectUri = "http://localhost:8888/callback"           # <-- HIER EINTRAGEN (oder Standard belassen)
    
    # -------------------------------------------------------------------------
    # VERSICHERTENDATEN
    # -------------------------------------------------------------------------
    
    # KVNR (Krankenversichertennummer) - 10-stellig
    # Format: Buchstabe + 9 Ziffern (z.B. "X123456789")
    KVNR = ""                                                    # <-- HIER EINTRAGEN
    
    # -------------------------------------------------------------------------
    # AUTHENTIFIZIERUNGSMETHODE
    # -------------------------------------------------------------------------
    # Optionen:
    #   "eGK"           - Authentifizierung mit elektronischer Gesundheitskarte
    #   "GesundheitsID" - Authentifizierung ueber sektoralen IDP (App-basiert)
    #   "SMC-B"         - Authentifizierung mit Institutionskarte (fuer Apotheken/Aerzte)
    # -------------------------------------------------------------------------
    
    AuthMethode = "GesundheitsID"                                # <-- HIER EINTRAGEN
    
    # -------------------------------------------------------------------------
    # eGK-AUTHENTIFIZIERUNG (nur wenn AuthMethode = "eGK")
    # -------------------------------------------------------------------------
    
    # Konnektor-URL (fuer eGK-Zugriff ueber das Primaersystem-Konnektor)
    KonnektorUrl = ""                                            # <-- HIER EINTRAGEN (bei eGK)
    
    # CardHandle der eGK (wird vom Konnektor bereitgestellt)
    EgkCardHandle = ""                                           # <-- HIER EINTRAGEN (bei eGK)
    
    # -------------------------------------------------------------------------
    # SEKTORALER IDP (nur wenn AuthMethode = "GesundheitsID")
    # -------------------------------------------------------------------------
    
    # Discovery-URL des sektoralen IDP (kassenspezifisch)
    SektoralerIdpDiscoveryUrl = ""                               # <-- HIER EINTRAGEN (bei GesundheitsID)
    # Beispiele:
    # TK:      https://idp.tk.de/.well-known/openid-configuration
    # AOK:     https://idp.aok.de/.well-known/openid-configuration
    # BARMER:  https://idp.barmer.de/.well-known/openid-configuration
}

# ============================================================================
#                    OPTIONALE KONFIGURATION
# ============================================================================

$OptionalConfig = @{
    # HTTP-Timeout in Sekunden
    HttpTimeoutSeconds = 30
    
    # Ausfuehrliche Protokollierung
    VerboseLogging = $true
    
    # Lokaler Port fuer OAuth Redirect (nur fuer Tests)
    LocalRedirectPort = 8888
    
    # FHIR-Version
    FhirVersion = "4.0.1"
    
    # Maximale Anzahl abzurufender Rezepte
    MaxRezepte = 50
    
    # Nur bestimmte Rezept-Status abrufen
    # Optionen: "ready", "in-progress", "completed", "cancelled"
    RezeptStatus = @("ready", "in-progress")
}

# ============================================================================
#                    HILFSFUNKTIONEN
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "OK", "DEBUG")][string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"  { "White" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "OK"    { "Green" }
        "DEBUG" { "Gray" }
    }
    
    if ($Level -eq "DEBUG" -and -not $OptionalConfig.VerboseLogging) { return }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-RandomBytes {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return $bytes
}

function ConvertTo-Base64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    param([Parameter(Mandatory)][string]$Base64Url)
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
    }
    return [Convert]::FromBase64String($base64)
}

function Get-Sha256Hash {
    param([Parameter(Mandatory)][byte[]]$Data)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    return $sha256.ComputeHash($Data)
}

# ============================================================================
#                    PKCE FUNKTIONEN (RFC 7636)
# ============================================================================

function New-PkceChallenge {
    # Code Verifier: 43-128 Zeichen, Base64URL-kodiert
    $verifierBytes = Get-RandomBytes -Length 32
    $codeVerifier = ConvertTo-Base64Url -Bytes $verifierBytes
    
    # Code Challenge: SHA256(code_verifier), Base64URL-kodiert
    $challengeHash = Get-Sha256Hash -Data ([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
    $codeChallenge = ConvertTo-Base64Url -Bytes $challengeHash
    
    return @{
        Verifier  = $codeVerifier
        Challenge = $codeChallenge
        Method    = "S256"
    }
}

# ============================================================================
#                    IDP DISCOVERY & AUTHENTIFIZIERUNG
# ============================================================================

<#
.SYNOPSIS
    Ruft die OIDC Discovery-Informationen vom IDP ab.
#>
function Get-IdpDiscovery {
    param([Parameter(Mandatory)][string]$IdpBaseUrl)
    
    Write-Log "Rufe IDP Discovery-Dokument ab..."
    
    $discoveryUrl = "$IdpBaseUrl/.well-known/openid-configuration"
    
    try {
        $discovery = Invoke-RestMethod -Uri $discoveryUrl -Method Get -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        Write-Log "IDP Discovery erfolgreich" -Level "OK"
        Write-Log "  Authorization Endpoint: $($discovery.authorization_endpoint)" -Level "DEBUG"
        Write-Log "  Token Endpoint: $($discovery.token_endpoint)" -Level "DEBUG"
        
        return $discovery
    }
    catch {
        Write-Log "Fehler beim Abrufen der IDP Discovery: $_" -Level "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Ruft die Discovery-Informationen vom zentralen IDP der TI ab.
#>
function Get-TiIdpDiscovery {
    Write-Log "Rufe TI-IDP Discovery-Dokument ab..."
    
    $discoveryUrl = "$($Config.IdpBaseUrl)/.well-known/openid-configuration"
    
    try {
        $discovery = Invoke-RestMethod -Uri $discoveryUrl -Method Get -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        Write-Log "TI-IDP Discovery erfolgreich" -Level "OK"
        return $discovery
    }
    catch {
        Write-Log "Fehler beim Abrufen der TI-IDP Discovery: $_" -Level "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Startet den OIDC Authorization Flow fuer die GesundheitsID.
#>
function Start-GesundheitsIdAuthFlow {
    param(
        [Parameter(Mandatory)][hashtable]$IdpDiscovery,
        [Parameter(Mandatory)][hashtable]$PkceChallenge
    )
    
    Write-Log "Starte GesundheitsID-Authentifizierung..."
    
    # State und Nonce generieren
    $state = ConvertTo-Base64Url -Bytes (Get-RandomBytes -Length 16)
    $nonce = ConvertTo-Base64Url -Bytes (Get-RandomBytes -Length 16)
    
    # Authorization URL aufbauen
    $authParams = @{
        response_type         = "code"
        client_id             = $Config.OidcClientId
        redirect_uri          = $Config.OidcRedirectUri
        scope                 = "openid e-rezept"
        state                 = $state
        nonce                 = $nonce
        code_challenge        = $PkceChallenge.Challenge
        code_challenge_method = $PkceChallenge.Method
    }
    
    $queryString = ($authParams.GetEnumerator() | ForEach-Object { 
        "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" 
    }) -join "&"
    
    $authorizationUrl = "$($IdpDiscovery.authorization_endpoint)?$queryString"
    
    Write-Log "Authorization URL generiert" -Level "OK"
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  MANUELLE AUTHENTIFIZIERUNG ERFORDERLICH                              " -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Bitte oeffnen Sie folgende URL in Ihrem Browser:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host $authorizationUrl -ForegroundColor White
    Write-Host ""
    Write-Host "Nach erfolgreicher Authentifizierung werden Sie zu einer lokalen URL" -ForegroundColor Yellow
    Write-Host "weitergeleitet. Kopieren Sie den 'code'-Parameter aus der URL." -ForegroundColor Yellow
    Write-Host ""
    
    return @{
        AuthorizationUrl = $authorizationUrl
        State            = $state
        Nonce            = $nonce
    }
}

<#
.SYNOPSIS
    Tauscht den Authorization Code gegen Access- und ID-Token.
#>
function Get-ERezeptTokens {
    param(
        [Parameter(Mandatory)][hashtable]$IdpDiscovery,
        [Parameter(Mandatory)][string]$AuthorizationCode,
        [Parameter(Mandatory)][string]$CodeVerifier
    )
    
    Write-Log "Tausche Authorization Code gegen Tokens..."
    
    $tokenParams = @{
        grant_type    = "authorization_code"
        code          = $AuthorizationCode
        redirect_uri  = $Config.OidcRedirectUri
        client_id     = $Config.OidcClientId
        code_verifier = $CodeVerifier
    }
    
    try {
        $tokenResponse = Invoke-RestMethod `
            -Uri $IdpDiscovery.token_endpoint `
            -Method Post `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $tokenParams `
            -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        Write-Log "Tokens erfolgreich erhalten" -Level "OK"
        Write-Log "  Token-Typ: $($tokenResponse.token_type)" -Level "DEBUG"
        Write-Log "  Gueltig fuer: $($tokenResponse.expires_in) Sekunden" -Level "DEBUG"
        
        return $tokenResponse
    }
    catch {
        Write-Log "Fehler beim Token-Austausch: $_" -Level "ERROR"
        throw
    }
}

# ============================================================================
#                    E-REZEPT FHIR-API FUNKTIONEN
# ============================================================================

<#
.SYNOPSIS
    Ruft alle verfuegbaren E-Rezepte fuer den Versicherten ab.
.DESCRIPTION
    Verwendet den FHIR-Endpunkt GET /Task um alle Rezepte abzurufen.
    Gemaess gemSpec_FD_eRp A_19113, A_19116.
#>
function Get-ERezepte {
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [string[]]$Status = @("ready", "in-progress"),
        [int]$MaxCount = 50
    )
    
    Write-Log "Rufe E-Rezepte ab..."
    
    # FHIR Task-Suche aufbauen
    $searchParams = @()
    
    # Status-Filter
    if ($Status.Count -gt 0) {
        $statusParam = ($Status | ForEach-Object { "status=$_" }) -join "&"
        $searchParams += $statusParam
    }
    
    # Anzahl begrenzen
    $searchParams += "_count=$MaxCount"
    
    # Sortierung (neueste zuerst)
    $searchParams += "_sort=-authored-on"
    
    $queryString = $searchParams -join "&"
    $taskUrl = "$($Config.ERezeptFdBaseUrl)/Task?$queryString"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept"        = "application/fhir+json;fhirVersion=$($OptionalConfig.FhirVersion)"
        "X-Request-Id"  = [Guid]::NewGuid().ToString()
    }
    
    try {
        Write-Log "  URL: $taskUrl" -Level "DEBUG"
        
        $response = Invoke-RestMethod `
            -Uri $taskUrl `
            -Method Get `
            -Headers $headers `
            -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        Write-Log "E-Rezepte erfolgreich abgerufen" -Level "OK"
        
        return $response
    }
    catch {
        Write-Log "Fehler beim Abrufen der E-Rezepte: $_" -Level "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Ruft ein einzelnes E-Rezept anhand der Task-ID ab.
#>
function Get-ERezeptById {
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$TaskId
    )
    
    Write-Log "Rufe E-Rezept $TaskId ab..."
    
    $taskUrl = "$($Config.ERezeptFdBaseUrl)/Task/$TaskId"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept"        = "application/fhir+json;fhirVersion=$($OptionalConfig.FhirVersion)"
        "X-Request-Id"  = [Guid]::NewGuid().ToString()
    }
    
    try {
        $response = Invoke-RestMethod `
            -Uri $taskUrl `
            -Method Get `
            -Headers $headers `
            -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        Write-Log "E-Rezept erfolgreich abgerufen" -Level "OK"
        
        return $response
    }
    catch {
        Write-Log "Fehler beim Abrufen des E-Rezepts: $_" -Level "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Ruft die Verordnung (MedicationRequest) zu einem E-Rezept ab.
#>
function Get-ERezeptVerordnung {
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$TaskId,
        [Parameter(Mandatory)][string]$AccessCode
    )
    
    Write-Log "Rufe Verordnung fuer Task $TaskId ab..."
    
    # $accept-Operation abrufen
    $acceptUrl = "$($Config.ERezeptFdBaseUrl)/Task/$TaskId/`$accept?ac=$AccessCode"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept"        = "application/fhir+json;fhirVersion=$($OptionalConfig.FhirVersion)"
        "X-Request-Id"  = [Guid]::NewGuid().ToString()
    }
    
    try {
        $response = Invoke-RestMethod `
            -Uri $acceptUrl `
            -Method Post `
            -Headers $headers `
            -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        Write-Log "Verordnung erfolgreich abgerufen" -Level "OK"
        
        return $response
    }
    catch {
        Write-Log "Fehler beim Abrufen der Verordnung: $_" -Level "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Zeigt die E-Rezepte in formatierter Form an.
#>
function Show-ERezepte {
    param([Parameter(Mandatory)]$FhirBundle)
    
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "                         E-REZEPT UEBERSICHT                            " -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($null -eq $FhirBundle.entry -or $FhirBundle.entry.Count -eq 0) {
        Write-Host "  Keine E-Rezepte gefunden." -ForegroundColor Yellow
        Write-Host ""
        return
    }
    
    $totalRezepte = if ($FhirBundle.total) { $FhirBundle.total } else { $FhirBundle.entry.Count }
    Write-Host "  Gefundene E-Rezepte: $totalRezepte" -ForegroundColor White
    Write-Host ""
    
    $index = 1
    foreach ($entry in $FhirBundle.entry) {
        $task = $entry.resource
        
        if ($task.resourceType -ne "Task") { continue }
        
        # Task-Informationen extrahieren
        $taskId = $task.id
        $status = $task.status
        $authoredOn = if ($task.authoredOn) { 
            [DateTime]::Parse($task.authoredOn).ToString("dd.MM.yyyy HH:mm") 
        } else { "Unbekannt" }
        
        # Rezept-Typ ermitteln (PZN, Freitext, etc.)
        $flowType = "Unbekannt"
        if ($task.extension) {
            $flowTypeExt = $task.extension | Where-Object { 
                $_.url -like "*flowType*" -or $_.url -like "*PrescriptionType*" 
            }
            if ($flowTypeExt) {
                $flowType = switch ($flowTypeExt.valueCoding.code) {
                    "160" { "Muster 16 (Apothekenpflichtig)" }
                    "169" { "Muster 16 (Direktzuweisung)" }
                    "200" { "PKV" }
                    "209" { "PKV (Direktzuweisung)" }
                    default { $flowTypeExt.valueCoding.code }
                }
            }
        }
        
        # AccessCode extrahieren (falls vorhanden)
        $accessCode = $null
        if ($task.identifier) {
            $accessCodeId = $task.identifier | Where-Object { 
                $_.system -like "*AccessCode*" -or $_.system -like "*access-code*" 
            }
            if ($accessCodeId) {
                $accessCode = $accessCodeId.value
            }
        }
        
        # Prescriptions-ID extrahieren
        $prescriptionId = $null
        if ($task.identifier) {
            $prescriptionIdent = $task.identifier | Where-Object { 
                $_.system -like "*PrescriptionID*" -or $_.system -like "*prescription-id*" 
            }
            if ($prescriptionIdent) {
                $prescriptionId = $prescriptionIdent.value
            }
        }
        
        # Status-Farbe
        $statusColor = switch ($status) {
            "ready"       { "Green" }
            "in-progress" { "Yellow" }
            "completed"   { "Gray" }
            "cancelled"   { "Red" }
            default       { "White" }
        }
        
        Write-Host "  +-------------------------------------------------------------------------+" -ForegroundColor DarkGray
        Write-Host "  | Rezept #$index" -ForegroundColor White -NoNewline
        Write-Host "                                                              |" -ForegroundColor DarkGray
        Write-Host "  +-------------------------------------------------------------------------+" -ForegroundColor DarkGray
        Write-Host "  |  Task-ID:        " -ForegroundColor Gray -NoNewline
        Write-Host "$taskId" -ForegroundColor White
        Write-Host "  |  Status:         " -ForegroundColor Gray -NoNewline
        Write-Host "$status" -ForegroundColor $statusColor
        Write-Host "  |  Rezept-Typ:     " -ForegroundColor Gray -NoNewline
        Write-Host "$flowType" -ForegroundColor White
        Write-Host "  |  Ausgestellt am: " -ForegroundColor Gray -NoNewline
        Write-Host "$authoredOn" -ForegroundColor White
        
        if ($prescriptionId) {
            Write-Host "  |  Rezept-Nr:      " -ForegroundColor Gray -NoNewline
            Write-Host "$prescriptionId" -ForegroundColor Cyan
        }
        
        if ($accessCode -and $status -eq "ready") {
            Write-Host "  |  AccessCode:     " -ForegroundColor Gray -NoNewline
            Write-Host "$($accessCode.Substring(0, [Math]::Min(20, $accessCode.Length)))..." -ForegroundColor Magenta
        }
        
        Write-Host "  +-------------------------------------------------------------------------+" -ForegroundColor DarkGray
        Write-Host ""
        
        $index++
    }
    
    # Zusammenfassung
    $readyCount = ($FhirBundle.entry | Where-Object { $_.resource.status -eq "ready" }).Count
    $inProgressCount = ($FhirBundle.entry | Where-Object { $_.resource.status -eq "in-progress" }).Count
    
    Write-Host "  -------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Zusammenfassung:" -ForegroundColor White
    Write-Host "    Einloesbar (ready):      $readyCount" -ForegroundColor Green
    Write-Host "    In Bearbeitung:          $inProgressCount" -ForegroundColor Yellow
    Write-Host ""
}

<#
.SYNOPSIS
    Generiert einen QR-Code-aehnlichen Text fuer ein E-Rezept.
.DESCRIPTION
    Der DataMatrix-Code enthaelt die Task-ID und den AccessCode.
#>
function Get-ERezeptDataMatrix {
    param(
        [Parameter(Mandatory)][string]$TaskId,
        [Parameter(Mandatory)][string]$AccessCode
    )
    
    # DataMatrix-Inhalt gemaess gematik Spezifikation
    $dataMatrixContent = @{
        urls = @("Task/$TaskId/`$accept?ac=$AccessCode")
    } | ConvertTo-Json -Compress
    
    return $dataMatrixContent
}

# ============================================================================
#                    KONFIGURATIONSPRUEFUNG
# ============================================================================

function Test-Configuration {
    Write-Log "Pruefe Konfiguration..."
    
    $errors = @()
    
    # Pflichtfelder pruefen
    if ([string]::IsNullOrWhiteSpace($Config.ERezeptFdBaseUrl)) {
        $errors += "ERezeptFdBaseUrl nicht konfiguriert"
    }
    
    if ([string]::IsNullOrWhiteSpace($Config.IdpBaseUrl)) {
        $errors += "IdpBaseUrl nicht konfiguriert"
    }
    
    if ([string]::IsNullOrWhiteSpace($Config.OidcClientId)) {
        $errors += "OidcClientId nicht konfiguriert"
    }
    
    if ([string]::IsNullOrWhiteSpace($Config.KVNR)) {
        $errors += "KVNR nicht konfiguriert"
    } elseif ($Config.KVNR -notmatch "^[A-Z][0-9]{9}$") {
        $errors += "KVNR hat ungueltiges Format (erwartet: Buchstabe + 9 Ziffern)"
    }
    
    # Authentifizierungsmethode pruefen
    if ($Config.AuthMethode -eq "GesundheitsID") {
        if ([string]::IsNullOrWhiteSpace($Config.SektoralerIdpDiscoveryUrl)) {
            $errors += "SektoralerIdpDiscoveryUrl nicht konfiguriert (erforderlich fuer GesundheitsID)"
        }
    } elseif ($Config.AuthMethode -eq "eGK") {
        if ([string]::IsNullOrWhiteSpace($Config.KonnektorUrl)) {
            $errors += "KonnektorUrl nicht konfiguriert (erforderlich fuer eGK)"
        }
    }
    
    if ($errors.Count -gt 0) {
        Write-Host ""
        Write-Host "========================================================================" -ForegroundColor Red
        Write-Host "  KONFIGURATIONSFEHLER - Bitte folgende Werte im Skript eintragen:      " -ForegroundColor Red
        Write-Host "========================================================================" -ForegroundColor Red
        foreach ($err in $errors) {
            Write-Host "  X $err" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "Bearbeiten Sie den Abschnitt 'PFLICHT-KONFIGURATION' am Anfang des Skripts." -ForegroundColor Yellow
        Write-Host ""
        return $false
    }
    
    Write-Log "Konfiguration gueltig" -Level "OK"
    return $true
}

# ============================================================================
#                    HAUPTPROGRAMM
# ============================================================================

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "         E-Rezept Testskript (gemaess Gematik-Spezifikation)           " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Konfiguration pruefen
if (-not (Test-Configuration)) {
    exit 1
}

Write-Log "Umgebung: $($Config.Umgebung)"
Write-Log "KVNR: $($Config.KVNR.Substring(0,3))****$($Config.KVNR.Substring(7))"
Write-Log "Authentifizierung: $($Config.AuthMethode)"

try {
    # ==========================================================================
    # SCHRITT 1: IDP Discovery
    # ==========================================================================
    Write-Host ""
    Write-Log "=== SCHRITT 1: IDP Discovery ==="
    
    $idpDiscovery = $null
    
    if ($Config.AuthMethode -eq "GesundheitsID") {
        # Sektoraler IDP fuer GesundheitsID
        $idpDiscovery = Get-IdpDiscovery -IdpBaseUrl $Config.SektoralerIdpDiscoveryUrl.TrimEnd("/.well-known/openid-configuration")
    } else {
        # Zentraler TI-IDP
        $idpDiscovery = Get-TiIdpDiscovery
    }
    
    # ==========================================================================
    # SCHRITT 2: PKCE Challenge generieren
    # ==========================================================================
    Write-Host ""
    Write-Log "=== SCHRITT 2: PKCE Challenge generieren ==="
    
    $pkceChallenge = New-PkceChallenge
    Write-Log "PKCE Challenge erstellt" -Level "OK"
    Write-Log "  Verifier-Laenge: $($pkceChallenge.Verifier.Length) Zeichen" -Level "DEBUG"
    
    # ==========================================================================
    # SCHRITT 3: Authentifizierung starten
    # ==========================================================================
    Write-Host ""
    Write-Log "=== SCHRITT 3: Authentifizierung ==="
    
    $authResult = Start-GesundheitsIdAuthFlow -IdpDiscovery $idpDiscovery -PkceChallenge $pkceChallenge
    
    # Auf Authorization Code warten
    $authorizationCode = Read-Host "Bitte Authorization Code eingeben"
    
    if ([string]::IsNullOrWhiteSpace($authorizationCode)) {
        Write-Log "Kein Authorization Code eingegeben. Abbruch." -Level "ERROR"
        exit 1
    }
    
    # ==========================================================================
    # SCHRITT 4: Tokens abrufen
    # ==========================================================================
    Write-Host ""
    Write-Log "=== SCHRITT 4: Tokens abrufen ==="
    
    $tokens = Get-ERezeptTokens -IdpDiscovery $idpDiscovery -AuthorizationCode $authorizationCode -CodeVerifier $pkceChallenge.Verifier
    
    # ==========================================================================
    # SCHRITT 5: E-Rezepte abrufen
    # ==========================================================================
    Write-Host ""
    Write-Log "=== SCHRITT 5: E-Rezepte abrufen ==="
    
    $eRezepte = Get-ERezepte `
        -AccessToken $tokens.access_token `
        -Status $OptionalConfig.RezeptStatus `
        -MaxCount $OptionalConfig.MaxRezepte
    
    # ==========================================================================
    # SCHRITT 6: Ergebnisse anzeigen
    # ==========================================================================
    Write-Host ""
    Write-Log "=== SCHRITT 6: Ergebnisse ==="
    
    Show-ERezepte -FhirBundle $eRezepte
    
    # Optional: Als JSON speichern
    $outputFile = Join-Path $ScriptRoot "erezepte_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $eRezepte | ConvertTo-Json -Depth 20 | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Log "Ergebnisse gespeichert in: $outputFile" -Level "OK"
    
}
catch {
    Write-Log "Unbehandelter Fehler: $_" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "DEBUG"
    exit 1
}

Write-Host ""
Write-Log "=== E-Rezept-Abfrage abgeschlossen ===" -Level "OK"
Write-Host ""
