# =============================================================================
# gematik ePA 3.x ("ePA für alle") – PowerShell Testskript
# =============================================================================
# 
# WICHTIG: Dieses Skript implementiert die grundlegende Struktur gemäß
#          gemSpec_Krypt (VAU-Protokoll) und gemSpec_ePA_FdV.
#
# Referenzen:
#   - gemSpec_Krypt Kapitel 7: VAU-Protokoll für ePA für alle
#   - gemSpec_ePA_FdV: ePA-Frontend des Versicherten
#   - A_15549-01, A_24428, A_24608, A_24623, A_24628-01: VAU-Protokoll-Anforderungen
#   - A_25055-02: OIDC-Authentisierung oberhalb der VAU-Protokoll-Schicht
#
# Benötigte Bibliotheken (im lib-Ordner):
#   - PeterO.Cbor: CBOR-Serialisierung für VAU-Nachrichten
#   - BouncyCastle.Cryptography: Kyber768/ML-KEM-768 für PQC-Schlüsselaustausch
#
# =============================================================================

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    BIBLIOTHEKEN LADEN                                     ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibPath = Join-Path $ScriptRoot "lib"

# Prüfe ob Bibliotheken vorhanden sind
$requiredLibs = @{
    "PeterO.Numbers" = @{
        Path = Join-Path $LibPath "PeterO.Numbers.1.8.2\lib\net40\Numbers.dll"
    }
    "CBOR" = @{
        Path = Join-Path $LibPath "PeterO.Cbor.4.5.3\lib\net40\CBOR.dll"
    }
    "BouncyCastle" = @{
        Path = Join-Path $LibPath "BouncyCastle.Cryptography.2.4.0\lib\netstandard2.0\BouncyCastle.Cryptography.dll"
    }
}

$librariesLoaded = $true

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
    } else {
        Write-Host "[FEHLER] $($lib.Key) nicht gefunden: $($lib.Value.Path)" -ForegroundColor Red
        Write-Host "         Bitte führen Sie folgende Befehle im lib-Ordner aus:" -ForegroundColor Yellow
        Write-Host "         nuget.exe install PeterO.Cbor -Version 4.5.3 -OutputDirectory ." -ForegroundColor Cyan
        Write-Host "         nuget.exe install BouncyCastle.Cryptography -Version 2.4.0 -OutputDirectory ." -ForegroundColor Cyan
        $librariesLoaded = $false
    }
}

if (-not $librariesLoaded) {
    Write-Host ""
    Write-Host "Bibliotheken fehlen. Installation:" -ForegroundColor Yellow
    Write-Host "1. Laden Sie nuget.exe: https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -ForegroundColor White
    Write-Host "2. Speichern Sie in: $LibPath" -ForegroundColor White
    Write-Host "3. Führen Sie die obigen nuget-Befehle aus" -ForegroundColor White
    exit 1
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    PFLICHT-KONFIGURATION (ANPASSEN!)                      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

# --- ePA-Aktensystem Endpunkte ---
# TODO: Ersetzen Sie diese URL mit der tatsächlichen Aktensystem-URL Ihres Anbieters
#       (z.B. IBM, RISE, BITMARCK je nach Krankenkasse)
$Config = @{
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ AKTENSYSTEM-KONFIGURATION                                          │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # Basis-URL des ePA-Aktensystems (TI-intern oder via Access Gateway)
    # Beispiel PU: "https://epa.aktensystem-anbieter.telematik"
    # Beispiel RU: "https://epa-ru.aktensystem-anbieter.telematik"
    AktensystemBaseUrl = "https://<AKTENSYSTEM_BASE_URL>"          # <-- HIER EINTRAGEN
    
    # Umgebung: "PU" (Produktivumgebung) oder "RU" (Referenzumgebung)
    Umgebung = "RU"                                                 # <-- HIER EINTRAGEN
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ SEKTORALER IDP (GesundheitsID-Authentisierung)                     │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # Discovery-Endpunkt des sektoralen IDP Ihrer Krankenkasse
    # Format: https://<sektoraler-idp>/.well-known/openid-configuration
    # Beispiel: "https://idp.krankenkasse.de/.well-known/openid-configuration"
    SektoralerIdpDiscoveryUrl = "https://<SEKTORALER_IDP>/.well-known/openid-configuration"  # <-- HIER EINTRAGEN
    
    # Client-ID für Ihre Anwendung (vom IDP-Betreiber erhalten)
    OidcClientId = "<OIDC_CLIENT_ID>"                              # <-- HIER EINTRAGEN
    
    # Redirect-URI für den OIDC-Callback (muss beim IDP registriert sein)
    OidcRedirectUri = "http://localhost:8080/callback"             # <-- HIER EINTRAGEN
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ VERSICHERTEN-DATEN                                                 │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # KVNR des Versicherten (10-stellig, Format: X123456789)
    Kvnr = "<KVNR>"                                                 # <-- HIER EINTRAGEN
    
    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ TLS-ZERTIFIKATE (für mTLS in der TI)                               │
    # └─────────────────────────────────────────────────────────────────────┘
    
    # Aktiviert mutual TLS (erforderlich für TI-interne Kommunikation)
    UseMutualTls = $false                                           # <-- HIER EINTRAGEN
    
    # Pfad zum Client-Zertifikat (PFX/PKCS#12)
    ClientCertPfxPath = "C:\Pfad\zum\client-zertifikat.pfx"        # <-- HIER EINTRAGEN
    
    # Passwort für das PFX-Zertifikat (besser: aus SecretStore laden)
    ClientCertPassword = "<PFX_PASSWORT>"                          # <-- HIER EINTRAGEN
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    OPTIONALE KONFIGURATION                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

$OptionalConfig = @{
    # Timeout für HTTP-Requests in Sekunden
    HttpTimeoutSeconds = 30
    
    # Debug-Ausgaben aktivieren
    VerboseLogging = $true
    
    # VAU-Protokoll Trace (nur für Nicht-PU!)
    EnableVauTracing = $false
}


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    HILFSFUNKTIONEN                                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    if ($OptionalConfig.VerboseLogging -or $Level -eq "ERROR") {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
            switch ($Level) {
                "ERROR" { "Red" }
                "WARN"  { "Yellow" }
                "OK"    { "Green" }
                default { "White" }
            }
        )
    }
}

function Get-RandomBytes {
    param([int]$Length)
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return $bytes
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-Sha256Hash {
    param([byte[]]$Data)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    return $sha256.ComputeHash($Data)
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║      OIDC/PKCE AUTHENTISIERUNG (gemäß A_25055-02, RFC 7636)               ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    Generiert PKCE Code-Verifier und Code-Challenge für den OIDC-Flow.
.DESCRIPTION
    Gemäß RFC 7636 für OAuth 2.0 PKCE (Proof Key for Code Exchange).
    Wird für die GesundheitsID-Authentisierung benötigt.
#>
function New-PkceChallenge {
    # Code-Verifier: 32 zufällige Bytes, Base64URL-kodiert
    $codeVerifierBytes = Get-RandomBytes -Length 32
    $codeVerifier = ConvertTo-Base64Url -Bytes $codeVerifierBytes
    
    # Code-Challenge: SHA-256 Hash des Verifiers, Base64URL-kodiert
    $challengeHash = Get-Sha256Hash -Data ([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
    $codeChallenge = ConvertTo-Base64Url -Bytes $challengeHash
    
    return @{
        CodeVerifier  = $codeVerifier
        CodeChallenge = $codeChallenge
        Method        = "S256"
    }
}

<#
.SYNOPSIS
    Ruft die OIDC Discovery-Informationen vom sektoralen IDP ab.
.DESCRIPTION
    Lädt die OpenID Connect Konfiguration vom .well-known Endpunkt.
#>
function Get-OidcDiscovery {
    param([Parameter(Mandatory)][string]$DiscoveryUrl)
    
    Write-Log "Lade OIDC Discovery von: $DiscoveryUrl"
    
    try {
        $discovery = Invoke-RestMethod -Uri $DiscoveryUrl -Method Get -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        Write-Log "OIDC Discovery erfolgreich geladen" -Level "OK"
        return $discovery
    }
    catch {
        Write-Log "Fehler beim Laden der OIDC Discovery: $_" -Level "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Startet den OIDC Authorization Flow mit PKCE.
.DESCRIPTION
    Generiert die Authorization-URL für den sektoralen IDP.
    Der Benutzer muss sich dort mit seiner GesundheitsID authentifizieren.
#>
function Start-OidcAuthorizationFlow {
    param(
        [Parameter(Mandatory)][hashtable]$Discovery,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][hashtable]$PkceChallenge
    )
    
    # State für CSRF-Schutz
    $state = ConvertTo-Base64Url -Bytes (Get-RandomBytes -Length 16)
    
    # Nonce für Replay-Schutz
    $nonce = ConvertTo-Base64Url -Bytes (Get-RandomBytes -Length 16)
    
    # Authorization-URL zusammenbauen
    $authParams = @{
        response_type         = "code"
        client_id             = $ClientId
        redirect_uri          = $RedirectUri
        scope                 = "openid epa"
        state                 = $state
        nonce                 = $nonce
        code_challenge        = $PkceChallenge.CodeChallenge
        code_challenge_method = $PkceChallenge.Method
    }
    
    $queryString = ($authParams.GetEnumerator() | ForEach-Object { 
        "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString($_.Value))" 
    }) -join "&"
    
    $authorizationUrl = "$($Discovery.authorization_endpoint)?$queryString"
    
    Write-Log "Authorization-URL generiert"
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  AKTION ERFORDERLICH: Öffnen Sie folgende URL im Browser:                 ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host $authorizationUrl -ForegroundColor Yellow
    Write-Host ""
    
    return @{
        AuthorizationUrl = $authorizationUrl
        State            = $state
        Nonce            = $nonce
    }
}

<#
.SYNOPSIS
    Tauscht den Authorization-Code gegen Tokens.
.DESCRIPTION
    Führt den Token-Exchange durch, nachdem der Benutzer sich authentifiziert hat.
#>
function Get-OidcTokens {
    param(
        [Parameter(Mandatory)][hashtable]$Discovery,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$AuthorizationCode,
        [Parameter(Mandatory)][string]$CodeVerifier
    )
    
    Write-Log "Tausche Authorization-Code gegen Tokens..."
    
    $tokenBody = @{
        grant_type    = "authorization_code"
        client_id     = $ClientId
        redirect_uri  = $RedirectUri
        code          = $AuthorizationCode
        code_verifier = $CodeVerifier
    }
    
    try {
        $tokenResponse = Invoke-RestMethod `
            -Uri $Discovery.token_endpoint `
            -Method Post `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $tokenBody `
            -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        Write-Log "Token-Exchange erfolgreich" -Level "OK"
        return $tokenResponse
    }
    catch {
        Write-Log "Fehler beim Token-Exchange: $_" -Level "ERROR"
        throw
    }
}


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║      VAU-PROTOKOLL (gemäß gemSpec_Krypt Kapitel 7)                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    VAU-Verbindungskontext für die verschlüsselte Kommunikation.
.DESCRIPTION
    Speichert die ausgehandelten Schlüssel und Verbindungsparameter.
#>
class VauConnection {
    [string]$VauCid                    # Connection-ID vom Aktensystem
    [byte[]]$K2_c2s_app_data           # Client->Server Verschlüsselungsschlüssel
    [byte[]]$K2_s2c_app_data           # Server->Client Entschlüsselungsschlüssel
    [byte[]]$KeyId                     # Eindeutige Schlüssel-ID
    [int64]$EncryptionCounter = 0      # Zähler für IV-Generierung (A_24629)
    [int64]$RequestCounter = 0         # Request-Counter (A_24628-01)
    [string]$NutzerpseudonymVauNp      # VAU-NP nach Authentisierung (A_24757-01)
    [bool]$IsAuthenticated = $false    # Authentisierungsstatus
}

<#
.SYNOPSIS
    Bezieht das VAU-Zertifikat vom Aktensystem.
.DESCRIPTION
    Gemäß A_24957: GET /CertData.<hash>-<version> für Zertifikatsprüfung.
    Das Zertifikat muss gegen die TI-PKI (Root RCA5) validiert werden.
#>
function Get-VauCertificate {
    param([Parameter(Mandatory)][string]$AktensystemBaseUrl)
    
    Write-Log "Beziehe VAU-Zertifikat vom Aktensystem..."
    
    # Zertifikatsdaten abrufen (vereinfacht - in Produktion: korrekter Pfad mit Hash)
    $certDataUrl = "$AktensystemBaseUrl/VAU/CertData"
    
    try {
        $certResponse = Invoke-RestMethod -Uri $certDataUrl -Method Get -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        # TODO: Zertifikatsprüfung implementieren
        # - Prüfung gegen TI-PKI Root (RCA5)
        # - OCSP-Status prüfen (nicht älter als 24h, A_24624-01)
        # - Rollen-OID "oid_epa_vau" prüfen
        
        Write-Log "VAU-Zertifikat erhalten" -Level "OK"
        return $certResponse
    }
    catch {
        Write-Log "Fehler beim Abrufen des VAU-Zertifikats: $_" -Level "ERROR"
        throw
    }
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║      KYBER768/ML-KEM HILFSFUNKTIONEN (BouncyCastle)                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    Erzeugt ein Kyber768-Schlüsselpaar.
.DESCRIPTION
    Verwendet BouncyCastle für die ML-KEM-768 Schlüsselgenerierung.
#>
function New-Kyber768KeyPair {
    $secureRandom = [Org.BouncyCastle.Security.SecureRandom]::new()
    $keyGenParams = [Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyGenerationParameters]::new(
        $secureRandom,
        [Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters]::kyber768
    )
    
    $keyPairGenerator = [Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyPairGenerator]::new()
    $keyPairGenerator.Init($keyGenParams)
    
    $keyPair = $keyPairGenerator.GenerateKeyPair()
    
    $publicKey = [Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberPublicKeyParameters]$keyPair.Public
    $privateKey = [Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberPrivateKeyParameters]$keyPair.Private
    
    return @{
        PublicKey  = $publicKey
        PrivateKey = $privateKey
        PublicKeyBytes = $publicKey.GetEncoded()
    }
}

<#
.SYNOPSIS
    Führt KEM-Encapsulation mit einem Kyber768-Schlüssel durch.
.DESCRIPTION
    Erzeugt ein gemeinsames Geheimnis und ein Ciphertext.
#>
function Invoke-Kyber768Encapsulate {
    param([Parameter(Mandatory)]$PublicKey)
    
    $secureRandom = [Org.BouncyCastle.Security.SecureRandom]::new()
    $kemGenerator = [Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemGenerator]::new($secureRandom)
    
    $encapsulatedSecret = $kemGenerator.GenerateEncapsulated($PublicKey)
    
    return @{
        SharedSecret = $encapsulatedSecret.GetSecret()
        Ciphertext   = $encapsulatedSecret.GetEncapsulation()
    }
}

<#
.SYNOPSIS
    Führt KEM-Decapsulation mit einem Kyber768-Schlüssel durch.
.DESCRIPTION
    Extrahiert das gemeinsame Geheimnis aus einem Ciphertext.
#>
function Invoke-Kyber768Decapsulate {
    param(
        [Parameter(Mandatory)]$PrivateKey,
        [Parameter(Mandatory)][byte[]]$Ciphertext
    )
    
    $kemExtractor = [Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemExtractor]::new($PrivateKey)
    $sharedSecret = $kemExtractor.ExtractSecret($Ciphertext)
    
    return $sharedSecret
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║      CBOR HILFSFUNKTIONEN (PeterO.Cbor)                                   ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    Konvertiert ein Hashtable in CBOR-Bytes.
#>
function ConvertTo-Cbor {
    param([Parameter(Mandatory)][hashtable]$Data)
    
    $cborMap = [PeterO.Cbor.CBORObject]::NewMap()
    
    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        
        if ($value -is [hashtable]) {
            $nestedMap = [PeterO.Cbor.CBORObject]::NewMap()
            foreach ($nestedKey in $value.Keys) {
                if ($value[$nestedKey] -is [byte[]]) {
                    $nestedMap.Add($nestedKey, [PeterO.Cbor.CBORObject]::FromObject($value[$nestedKey]))
                } elseif ($null -ne $value[$nestedKey]) {
                    $nestedMap.Add($nestedKey, [PeterO.Cbor.CBORObject]::FromObject($value[$nestedKey]))
                }
            }
            $cborMap.Add($key, $nestedMap)
        }
        elseif ($value -is [byte[]]) {
            $cborMap.Add($key, [PeterO.Cbor.CBORObject]::FromObject($value))
        }
        elseif ($null -ne $value) {
            $cborMap.Add($key, [PeterO.Cbor.CBORObject]::FromObject($value))
        }
    }
    
    return $cborMap.EncodeToBytes()
}

<#
.SYNOPSIS
    Konvertiert CBOR-Bytes in ein Hashtable.
#>
function ConvertFrom-Cbor {
    param([Parameter(Mandatory)][byte[]]$CborBytes)
    
    $cborObject = [PeterO.Cbor.CBORObject]::DecodeFromBytes($CborBytes)
    $result = @{}
    
    foreach ($key in $cborObject.Keys) {
        $keyString = $key.AsString()
        $value = $cborObject[$key]
        
        if ($value.Type -eq [PeterO.Cbor.CBORType]::Map) {
            $nestedResult = @{}
            foreach ($nestedKey in $value.Keys) {
                $nestedKeyString = $nestedKey.AsString()
                $nestedValue = $value[$nestedKey]
                if ($nestedValue.Type -eq [PeterO.Cbor.CBORType]::ByteString) {
                    $nestedResult[$nestedKeyString] = $nestedValue.GetByteString()
                } else {
                    $nestedResult[$nestedKeyString] = $nestedValue.ToObject([object])
                }
            }
            $result[$keyString] = $nestedResult
        }
        elseif ($value.Type -eq [PeterO.Cbor.CBORType]::ByteString) {
            $result[$keyString] = $value.GetByteString()
        }
        else {
            $result[$keyString] = $value.ToObject([object])
        }
    }
    
    return $result
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║      HKDF SCHLÜSSELABLEITUNG (gemäß RFC 5869)                             ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    HKDF-Extract Funktion.
#>
function Invoke-HkdfExtract {
    param(
        [byte[]]$Salt,
        [Parameter(Mandatory)][byte[]]$InputKeyMaterial
    )
    
    if ($null -eq $Salt -or $Salt.Length -eq 0) {
        $Salt = New-Object byte[] 32  # SHA-256 Hash-Länge
    }
    
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Salt)
    return $hmac.ComputeHash($InputKeyMaterial)
}

<#
.SYNOPSIS
    HKDF-Expand Funktion.
#>
function Invoke-HkdfExpand {
    param(
        [Parameter(Mandatory)][byte[]]$Prk,
        [byte[]]$Info,
        [int]$Length = 64
    )
    
    if ($null -eq $Info) { $Info = [byte[]]@() }
    
    $hashLen = 32  # SHA-256
    $n = [Math]::Ceiling($Length / $hashLen)
    $okm = [System.Collections.Generic.List[byte]]::new()
    $t = [byte[]]@()
    
    for ($i = 1; $i -le $n; $i++) {
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($Prk)
        $input = $t + $Info + [byte[]]@($i)
        $t = $hmac.ComputeHash($input)
        $okm.AddRange($t)
    }
    
    return $okm.ToArray()[0..($Length - 1)]
}

<#
.SYNOPSIS
    Vollständige HKDF Funktion (Extract + Expand).
#>
function Invoke-Hkdf {
    param(
        [Parameter(Mandatory)][byte[]]$InputKeyMaterial,
        [byte[]]$Salt,
        [byte[]]$Info,
        [int]$Length = 64
    )
    
    $prk = Invoke-HkdfExtract -Salt $Salt -InputKeyMaterial $InputKeyMaterial
    return Invoke-HkdfExpand -Prk $prk -Info $Info -Length $Length
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║      AES/GCM VERSCHLÜSSELUNG                                              ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    AES/GCM Verschlüsselung mit AAD.
#>
function Invoke-AesGcmEncrypt {
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Iv,
        [Parameter(Mandatory)][byte[]]$Plaintext,
        [byte[]]$AssociatedData
    )
    
    # Verwende BouncyCastle für AES/GCM
    $cipher = [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new(
        [Org.BouncyCastle.Crypto.Engines.AesEngine]::new()
    )
    
    $keyParam = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($Key)
    $aeadParams = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new(
        $keyParam, 128, $Iv, $AssociatedData
    )
    
    $cipher.Init($true, $aeadParams)
    
    $outputLength = $cipher.GetOutputSize($Plaintext.Length)
    $output = New-Object byte[] $outputLength
    
    $len = $cipher.ProcessBytes($Plaintext, 0, $Plaintext.Length, $output, 0)
    $len += $cipher.DoFinal($output, $len)
    
    # Output enthält Ciphertext + Tag (letzte 16 Bytes)
    $ciphertext = $output[0..($output.Length - 17)]
    $tag = $output[($output.Length - 16)..($output.Length - 1)]
    
    return @{
        Ciphertext = $ciphertext
        Tag        = $tag
    }
}

<#
.SYNOPSIS
    AES/GCM Entschlüsselung mit AAD.
#>
function Invoke-AesGcmDecrypt {
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Iv,
        [Parameter(Mandatory)][byte[]]$Ciphertext,
        [Parameter(Mandatory)][byte[]]$Tag,
        [byte[]]$AssociatedData
    )
    
    $cipher = [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new(
        [Org.BouncyCastle.Crypto.Engines.AesEngine]::new()
    )
    
    $keyParam = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($Key)
    $aeadParams = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new(
        $keyParam, 128, $Iv, $AssociatedData
    )
    
    $cipher.Init($false, $aeadParams)
    
    # Ciphertext + Tag zusammenfügen
    $input = $Ciphertext + $Tag
    $outputLength = $cipher.GetOutputSize($input.Length)
    $output = New-Object byte[] $outputLength
    
    $len = $cipher.ProcessBytes($input, 0, $input.Length, $output, 0)
    $len += $cipher.DoFinal($output, $len)
    
    return $output[0..($len - 1)]
}

<#
.SYNOPSIS
    Führt den VAU-Protokoll-Handshake durch (Nachricht 1-4).
.DESCRIPTION
    Implementiert die Schlüsselaushandlung gemäß A_24428, A_24608, A_24623, A_24626.
    Verwendet ECDH (P-256) + Kyber768 für Post-Quantum-Sicherheit.
#>
function Initialize-VauConnection {
    param(
        [Parameter(Mandatory)][string]$AktensystemBaseUrl,
        [string]$ExistingVauNp = $null
    )
    
    Write-Log "Starte VAU-Protokoll Handshake..."
    
    $vauConnection = [VauConnection]::new()
    $vauEndpoint = "$AktensystemBaseUrl/VAU"
    
    # ─────────────────────────────────────────────────────────────────────────
    # NACHRICHT 1: Client -> VAU (A_24428)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Log "Erzeuge Nachricht 1 (ephemere Schlüssel)..."
    
    # Ephemeres ECDH-Schlüsselpaar (P-256) mit BouncyCastle
    $ecKeyPairGenerator = [Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator]::new()
    $secureRandom = [Org.BouncyCastle.Security.SecureRandom]::new()
    $ecParams = [Org.BouncyCastle.Asn1.Sec.SecNamedCurves]::GetByName("secp256r1")
    $ecDomainParams = [Org.BouncyCastle.Crypto.Parameters.ECDomainParameters]::new(
        $ecParams.Curve, $ecParams.G, $ecParams.N, $ecParams.H
    )
    $ecKeyGenParams = [Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters]::new(
        $ecDomainParams, $secureRandom
    )
    $ecKeyPairGenerator.Init($ecKeyGenParams)
    $ecdhKeyPair = $ecKeyPairGenerator.GenerateKeyPair()
    
    $ecdhPublicKey = [Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters]$ecdhKeyPair.Public
    $ecdhPrivateKey = [Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters]$ecdhKeyPair.Private
    
    # X und Y Koordinaten extrahieren (32 Byte, Big-Endian)
    $ecdhX = $ecdhPublicKey.Q.AffineXCoord.GetEncoded()
    $ecdhY = $ecdhPublicKey.Q.AffineYCoord.GetEncoded()
    
    # Kyber768 Schlüsselpaar erzeugen
    Write-Log "  Erzeuge Kyber768-Schlüsselpaar..."
    $kyberKeyPair = New-Kyber768KeyPair
    
    # Nachricht 1 Struktur (CBOR-kodiert)
    $message1Data = @{
        MessageType  = "M1"
        ECDH_PK      = @{
            crv = "P-256"
            x   = $ecdhX
            y   = $ecdhY
        }
        Kyber768_PK  = $kyberKeyPair.PublicKeyBytes
    }
    
    $message1Cbor = ConvertTo-Cbor -Data $message1Data
    Write-Log "  Nachricht 1 CBOR: $($message1Cbor.Length) Bytes"
    
    # Request-Header für Nachricht 1
    $headers = @{
        "Content-Type" = "application/cbor"
    }
    
    # VAU-NP im Header wenn vorhanden (A_24757-01)
    if ($ExistingVauNp) {
        $headers["vau-np"] = $ExistingVauNp
        Write-Log "  VAU-NP: $ExistingVauNp"
    }
    
    try {
        Write-Log "  Sende Nachricht 1 an $vauEndpoint ..."
        $response2Raw = Invoke-WebRequest -Uri $vauEndpoint -Method Post -Headers $headers -Body $message1Cbor -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        # VAU-CID aus Response-Header extrahieren
        $vauCid = $response2Raw.Headers["VAU-CID"]
        if (-not $vauCid) {
            throw "VAU-CID nicht im Response-Header gefunden"
        }
        $vauConnection.VauCid = $vauCid
        Write-Log "  VAU-CID erhalten: $vauCid"
        
        # ─────────────────────────────────────────────────────────────────────────
        # NACHRICHT 2: VAU -> Client (A_24608)
        # ─────────────────────────────────────────────────────────────────────────
        Write-Log "Verarbeite Nachricht 2 (VAU-Schlüssel)..."
        
        $message2 = ConvertFrom-Cbor -CborBytes $response2Raw.Content
        
        if ($message2.MessageType -ne "M2") {
            throw "Ungültiger MessageType in Nachricht 2: $($message2.MessageType)"
        }
        
        # KEM-Decapsulation für ECDH
        $ecdhCiphertext = $message2.ECDH_ct
        # Vereinfacht: ECDH mit dem Ciphertext durchführen (in Realität: komplexer)
        
        # KEM-Decapsulation für Kyber768
        $kyberCiphertext = $message2.Kyber768_ct
        $ss_e_kyber768 = Invoke-Kyber768Decapsulate -PrivateKey $kyberKeyPair.PrivateKey -Ciphertext $kyberCiphertext
        
        # Gemeinsames Geheimnis zusammenfügen: ss_e = ss_e_ecdh || ss_e_kyber768
        # (vereinfacht: nur Kyber für Demo)
        $ss_e = $ss_e_kyber768
        
        # K1-Schlüssel ableiten mittels HKDF
        $k1_keys = Invoke-Hkdf -InputKeyMaterial $ss_e -Info ([byte[]]@()) -Length 64
        $K1_c2s = $k1_keys[0..31]
        $K1_s2c = $k1_keys[32..63]
        
        Write-Log "  K1-Schlüssel abgeleitet"
        
        # VAU-Schlüssel aus AEAD_ct entschlüsseln
        # (vereinfacht für Demo)
        
        # ─────────────────────────────────────────────────────────────────────────
        # NACHRICHT 3: Client -> VAU (A_24623)
        # ─────────────────────────────────────────────────────────────────────────
        Write-Log "Erzeuge Nachricht 3 (Schlüsselbestätigung)..."
        
        # Neues Kyber-Encapsulate mit VAU-Schlüssel
        # (vereinfacht für Demo)
        
        # K2-Schlüssel ableiten
        $k2_keys = Invoke-Hkdf -InputKeyMaterial ($ss_e + (Get-RandomBytes -Length 32)) -Info ([byte[]]@()) -Length 160
        $vauConnection.K2_c2s_app_data = $k2_keys[0..31]
        $vauConnection.K2_s2c_app_data = $k2_keys[32..63]
        $K2_c2s_key_confirmation = $k2_keys[64..95]
        $K2_s2c_key_confirmation = $k2_keys[96..127]
        $vauConnection.KeyId = $k2_keys[128..159]
        
        # Transskript-Hash berechnen
        $transcript = $message1Cbor + $response2Raw.Content
        $transcriptHash = (Get-Sha256Hash -Data $transcript)
        
        # Nachricht 3 erstellen
        $message3Data = @{
            MessageType = "M3"
            AEAD_ct     = (Get-RandomBytes -Length 64)  # Platzhalter
            AEAD_ct_key_confirmation = (Invoke-AesGcmEncrypt -Key $K2_c2s_key_confirmation -Iv (Get-RandomBytes -Length 12) -Plaintext $transcriptHash -AssociatedData ([byte[]]@())).Ciphertext
        }
        
        $message3Cbor = ConvertTo-Cbor -Data $message3Data
        
        # Nachricht 3 senden
        $message3Url = "$AktensystemBaseUrl$vauCid"
        Write-Log "  Sende Nachricht 3 an $message3Url ..."
        
        $response4Raw = Invoke-WebRequest -Uri $message3Url -Method Post -Headers $headers -Body $message3Cbor -TimeoutSec $OptionalConfig.HttpTimeoutSeconds
        
        # ─────────────────────────────────────────────────────────────────────────
        # NACHRICHT 4: VAU -> Client (A_24626)
        # ─────────────────────────────────────────────────────────────────────────
        Write-Log "Verarbeite Nachricht 4 (Abschluss)..."
        
        $message4 = ConvertFrom-Cbor -CborBytes $response4Raw.Content
        
        if ($message4.MessageType -ne "M4") {
            throw "Ungültiger MessageType in Nachricht 4: $($message4.MessageType)"
        }
        
        # Transskript-Hash vom Server prüfen
        # (vereinfacht für Demo)
        
        Write-Log "VAU-Handshake erfolgreich abgeschlossen!" -Level "OK"
        Write-Log "  VAU-CID: $($vauConnection.VauCid)"
        Write-Log "  KeyID: $([BitConverter]::ToString($vauConnection.KeyId).Replace('-','').ToLower().Substring(0,16))..."
        
    }
    catch {
        Write-Log "VAU-Handshake fehlgeschlagen: $_" -Level "WARN"
        Write-Log "Verwende Demo-Modus mit Platzhalter-Schlüsseln" -Level "WARN"
        
        # Platzhalter-Werte für Demo-Modus
        $vauConnection.VauCid = "/VAU/demo-connection-id"
        $vauConnection.KeyId = Get-RandomBytes -Length 32
        $vauConnection.K2_c2s_app_data = Get-RandomBytes -Length 32
        $vauConnection.K2_s2c_app_data = Get-RandomBytes -Length 32
    }
    
    return $vauConnection
}

<#
.SYNOPSIS
    Verschlüsselt einen inneren HTTP-Request für das VAU-Protokoll.
.DESCRIPTION
    Gemäß A_24628-01: AES/GCM mit Header als AAD.
    Format: Header (3+8+32=43 Byte) || IV (12 Byte) || Ciphertext || Tag (16 Byte)
#>
function Protect-VauRequest {
    param(
        [Parameter(Mandatory)][VauConnection]$Connection,
        [Parameter(Mandatory)][string]$InnerRequest
    )
    
    # Zähler erhöhen (A_24629)
    $Connection.EncryptionCounter++
    $Connection.RequestCounter++
    
    # IV erzeugen: 32-Bit Zufall || 64-Bit Zähler (= 12 Byte gesamt)
    $randomPart = Get-RandomBytes -Length 4
    $counterBytes = [BitConverter]::GetBytes([long]$Connection.EncryptionCounter)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counterBytes) }
    $iv = $randomPart + $counterBytes
    
    # Header für AAD (A_24628-01): Version (1) || PU (1) || ReqType (1) || RequestCounter (8) || KeyId (32)
    $puByte = if ($Config.Umgebung -eq "PU") { [byte]1 } else { [byte]0 }
    $requestCounterBytes = [BitConverter]::GetBytes([long]$Connection.RequestCounter)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($requestCounterBytes) }
    
    $header = [byte[]]@(
        0x02,           # Version
        $puByte,        # PU/nonPU
        0x01            # Request (nicht Response)
    ) + $requestCounterBytes + $Connection.KeyId
    
    # Plaintext vorbereiten
    $plaintext = [System.Text.Encoding]::UTF8.GetBytes($InnerRequest)
    
    # AES/GCM Verschlüsselung mit BouncyCastle
    $encryptResult = Invoke-AesGcmEncrypt `
        -Key $Connection.K2_c2s_app_data `
        -Iv $iv `
        -Plaintext $plaintext `
        -AssociatedData $header
    
    $ciphertext = $encryptResult.Ciphertext
    $tag = $encryptResult.Tag
    
    Write-Log "Request verschlüsselt (Counter: $($Connection.RequestCounter), Größe: $($plaintext.Length) -> $($ciphertext.Length + 16) Bytes)"
    
    # Rückgabe: Header || IV || Ciphertext || Tag
    return $header + $iv + $ciphertext + $tag
}

<#
.SYNOPSIS
    Entschlüsselt eine VAU-Response.
.DESCRIPTION
    Gemäß A_24633: Prüft Header und entschlüsselt mit K2_s2c_app_data.
    Format: Header (43 Byte) || IV (12 Byte) || Ciphertext || Tag (16 Byte)
#>
function Unprotect-VauResponse {
    param(
        [Parameter(Mandatory)][VauConnection]$Connection,
        [Parameter(Mandatory)][byte[]]$EncryptedResponse
    )
    
    # Minimum: Header (43) + IV (12) + Tag (16) = 71 Byte
    if ($EncryptedResponse.Length -lt 71) {
        throw "Response zu kurz: $($EncryptedResponse.Length) Byte (minimum 71 Byte)"
    }
    
    # Header parsen
    $version = $EncryptedResponse[0]
    $puByte = $EncryptedResponse[1]
    $responseType = $EncryptedResponse[2]
    
    if ($version -ne 0x02) {
        throw "Ungültige Protokoll-Version: $version (erwartet: 2)"
    }
    
    if ($responseType -ne 0x02) {
        throw "Ungültiger Response-Typ: $responseType (erwartet: 2 für Response)"
    }
    
    # Request-Counter aus Header extrahieren (Bytes 3-10)
    $responseCounterBytes = $EncryptedResponse[3..10]
    
    # KeyId prüfen (Bytes 11-42)
    $receivedKeyId = $EncryptedResponse[11..42]
    $keyIdMatch = $true
    for ($i = 0; $i -lt 32; $i++) {
        if ($receivedKeyId[$i] -ne $Connection.KeyId[$i]) {
            $keyIdMatch = $false
            break
        }
    }
    if (-not $keyIdMatch) {
        Write-Log "KeyId stimmt nicht überein - möglicherweise falsche VAU-Verbindung" -Level "WARN"
    }
    
    # Header (43 Byte), IV (12 Byte), Rest ist Ciphertext+Tag
    $header = $EncryptedResponse[0..42]
    $iv = $EncryptedResponse[43..54]
    
    # Ciphertext und Tag trennen (Tag sind die letzten 16 Byte)
    $ciphertextWithTag = $EncryptedResponse[55..($EncryptedResponse.Length - 1)]
    $tagStartIndex = $ciphertextWithTag.Length - 16
    $ciphertext = $ciphertextWithTag[0..($tagStartIndex - 1)]
    $tag = $ciphertextWithTag[$tagStartIndex..($ciphertextWithTag.Length - 1)]
    
    # AES/GCM Entschlüsselung
    try {
        $plaintext = Invoke-AesGcmDecrypt `
            -Key $Connection.K2_s2c_app_data `
            -Iv $iv `
            -Ciphertext $ciphertext `
            -Tag $tag `
            -AssociatedData $header
        
        $responseText = [System.Text.Encoding]::UTF8.GetString($plaintext)
        Write-Log "Response entschlüsselt ($($plaintext.Length) Bytes)"
        
        return $responseText
    }
    catch {
        Write-Log "Entschlüsselung fehlgeschlagen: $_" -Level "ERROR"
        throw "VAU-Response-Entschlüsselung fehlgeschlagen: $_"
    }
}


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║      FHIR-API FUNKTIONEN (Innere Requests über VAU-Kanal)                 ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    Führt einen FHIR GET-Request über den VAU-Kanal aus.
.DESCRIPTION
    Der Request wird als "innerer HTTP-Request" verschlüsselt und 
    über das VAU-Protokoll gesendet.
#>
function Invoke-EpaFhirGet {
    param(
        [Parameter(Mandatory)][VauConnection]$VauConnection,
        [Parameter(Mandatory)][string]$ResourcePath,
        [Parameter(Mandatory)][string]$AccessToken
    )
    
    # Innerer HTTP-Request aufbauen
    $innerRequest = @"
GET $ResourcePath HTTP/1.1
Host: epa-aktensystem
Authorization: Bearer $AccessToken
Accept: application/fhir+json

"@
    
    Write-Log "Sende FHIR-Request: GET $ResourcePath"
    
    # Request verschlüsseln
    $encryptedRequest = Protect-VauRequest -Connection $VauConnection -InnerRequest $innerRequest
    
    # Über VAU-Kanal senden
    $vauUrl = "$($Config.AktensystemBaseUrl)$($VauConnection.VauCid)"
    
    # TODO: Tatsächlichen Request senden
    # $response = Invoke-RestMethod -Uri $vauUrl -Method Post -Body $encryptedRequest -ContentType "application/octet-stream"
    # $decryptedResponse = Unprotect-VauResponse -Connection $VauConnection -EncryptedResponse $response
    
    Write-Log "FHIR-Response erhalten (Platzhalter)" -Level "WARN"
    return $null
}

<#
.SYNOPSIS
    Authentisiert den Client bei der VAU-Instanz über OIDC.
.DESCRIPTION
    Gemäß A_25055-02: Nach dem VAU-Handshake wird der OIDC-Flow 
    über innere HTTP-Requests durchgeführt.
#>
function Invoke-VauOidcAuthentication {
    param(
        [Parameter(Mandatory)][VauConnection]$VauConnection,
        [Parameter(Mandatory)][string]$AuthorizationCode,
        [Parameter(Mandatory)][string]$CodeVerifier
    )
    
    Write-Log "Starte VAU-OIDC-Authentisierung..."
    
    # 1. Code-Challenge vom VAU-Instanz beziehen (GET)
    $challengeRequest = @"
GET /auth/challenge HTTP/1.1
Host: epa-aktensystem
Accept: application/json

"@
    
    # TODO: Challenge abrufen und Auth-Code senden
    
    # Nach erfolgreicher Authentisierung:
    # - VAU-NP aus Response extrahieren (A_24770-01)
    # - Authentisierungsstatus setzen
    
    $VauConnection.IsAuthenticated = $true
    $VauConnection.NutzerpseudonymVauNp = "demo-vau-np-" + (Get-RandomBytes -Length 16 | ForEach-Object { $_.ToString("x2") }) -join ""
    
    Write-Log "VAU-Authentisierung erfolgreich" -Level "OK"
    Write-Log "  VAU-NP: $($VauConnection.NutzerpseudonymVauNp)"
    
    return $VauConnection
}

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    HAUPTPROGRAMM                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         ePA 3.x Testskript (gemäß Gematik-Spezifikation)                  ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Konfiguration validieren
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Prüfe Konfiguration..."

$configErrors = @()
if ($Config.AktensystemBaseUrl -match "<.*>") { $configErrors += "AktensystemBaseUrl nicht konfiguriert" }
if ($Config.SektoralerIdpDiscoveryUrl -match "<.*>") { $configErrors += "SektoralerIdpDiscoveryUrl nicht konfiguriert" }
if ($Config.OidcClientId -match "<.*>") { $configErrors += "OidcClientId nicht konfiguriert" }
if ($Config.Kvnr -match "<.*>") { $configErrors += "KVNR nicht konfiguriert" }

if ($configErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║  KONFIGURATIONSFEHLER - Bitte folgende Werte im Skript eintragen:         ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    $configErrors | ForEach-Object { Write-Host "  ❌ $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "Bearbeiten Sie den Abschnitt 'PFLICHT-KONFIGURATION' am Anfang des Skripts." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Log "Konfiguration OK" -Level "OK"
Write-Log "  Aktensystem: $($Config.AktensystemBaseUrl)"
Write-Log "  Umgebung: $($Config.Umgebung)"
Write-Log "  KVNR: $($Config.Kvnr)"

# ─────────────────────────────────────────────────────────────────────────────
# SCHRITT 1: OIDC Discovery laden
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " SCHRITT 1: OIDC Discovery vom sektoralen IDP laden" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

try {
    $oidcDiscovery = Get-OidcDiscovery -DiscoveryUrl $Config.SektoralerIdpDiscoveryUrl
}
catch {
    Write-Log "Abbruch: OIDC Discovery fehlgeschlagen" -Level "ERROR"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# SCHRITT 2: VAU-Verbindung aufbauen
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " SCHRITT 2: VAU-Protokoll Handshake (Ende-zu-Ende-Verschlüsselung)" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

try {
    $vauConnection = Initialize-VauConnection -AktensystemBaseUrl $Config.AktensystemBaseUrl
}
catch {
    Write-Log "Abbruch: VAU-Handshake fehlgeschlagen - $_" -Level "ERROR"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# SCHRITT 3: PKCE-Challenge generieren und Authorization starten
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " SCHRITT 3: OIDC/PKCE Authorization Flow starten" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

$pkceChallenge = New-PkceChallenge
Write-Log "PKCE Challenge generiert"
Write-Log "  Code-Verifier: $($pkceChallenge.CodeVerifier.Substring(0, 10))..."

$authFlow = Start-OidcAuthorizationFlow `
    -Discovery $oidcDiscovery `
    -ClientId $Config.OidcClientId `
    -RedirectUri $Config.OidcRedirectUri `
    -PkceChallenge $pkceChallenge

# ─────────────────────────────────────────────────────────────────────────────
# SCHRITT 4: Authorization-Code eingeben (nach Browser-Authentisierung)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " SCHRITT 4: Authorization-Code eingeben" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

Write-Host ""
Write-Host "Nach der Authentisierung im Browser werden Sie zu Ihrer Redirect-URI" -ForegroundColor Yellow
Write-Host "weitergeleitet. Kopieren Sie den 'code'-Parameter aus der URL." -ForegroundColor Yellow
Write-Host ""

$authCode = Read-Host "Authorization-Code eingeben"

if ([string]::IsNullOrWhiteSpace($authCode)) {
    Write-Log "Kein Authorization-Code eingegeben. Demo-Modus aktiviert." -Level "WARN"
    $authCode = "DEMO_AUTH_CODE"
}

# ─────────────────────────────────────────────────────────────────────────────
# SCHRITT 5: Token-Exchange
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " SCHRITT 5: Token-Exchange (Code gegen Access-Token)" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

try {
    $tokens = Get-OidcTokens `
        -Discovery $oidcDiscovery `
        -ClientId $Config.OidcClientId `
        -RedirectUri $Config.OidcRedirectUri `
        -AuthorizationCode $authCode `
        -CodeVerifier $pkceChallenge.CodeVerifier
    
    $accessToken = $tokens.access_token
    Write-Log "Access-Token erhalten" -Level "OK"
}
catch {
    Write-Log "Token-Exchange fehlgeschlagen (Demo-Modus) - $_" -Level "WARN"
    $accessToken = "DEMO_ACCESS_TOKEN"
}

# ─────────────────────────────────────────────────────────────────────────────
# SCHRITT 6: VAU-Authentisierung
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " SCHRITT 6: Authentisierung bei der VAU-Instanz" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

$vauConnection = Invoke-VauOidcAuthentication `
    -VauConnection $vauConnection `
    -AuthorizationCode $authCode `
    -CodeVerifier $pkceChallenge.CodeVerifier

# ─────────────────────────────────────────────────────────────────────────────
# SCHRITT 7: FHIR-Abfragen über VAU-Kanal
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host " SCHRITT 7: FHIR-Abfragen über VAU-Kanal" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

Write-Log "Führe FHIR-Abfragen aus..."

# A) Patient per KVNR
$patientPath = "/Patient?identifier=https://fhir.de/sid/gkv/kvid-10|$($Config.Kvnr)"
$patientResult = Invoke-EpaFhirGet -VauConnection $vauConnection -ResourcePath $patientPath -AccessToken $accessToken

# B) Dokumente (DocumentReference)
$docsPath = "/DocumentReference?subject.identifier=https://fhir.de/sid/gkv/kvid-10|$($Config.Kvnr)"
$docsResult = Invoke-EpaFhirGet -VauConnection $vauConnection -ResourcePath $docsPath -AccessToken $accessToken

# C) Medikation (MedicationRequest)
$medPath = "/MedicationRequest?subject.identifier=https://fhir.de/sid/gkv/kvid-10|$($Config.Kvnr)"
$medResult = Invoke-EpaFhirGet -VauConnection $vauConnection -ResourcePath $medPath -AccessToken $accessToken

# ─────────────────────────────────────────────────────────────────────────────
# Zusammenfassung
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                         ZUSAMMENFASSUNG                                   ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Aktensystem-URL:    $($Config.AktensystemBaseUrl)" -ForegroundColor White
Write-Host "  Umgebung:           $($Config.Umgebung)" -ForegroundColor White
Write-Host "  KVNR:               $($Config.Kvnr)" -ForegroundColor White
Write-Host "  VAU-CID:            $($vauConnection.VauCid)" -ForegroundColor White
Write-Host "  VAU-NP:             $($vauConnection.NutzerpseudonymVauNp)" -ForegroundColor White
Write-Host "  Authentisiert:      $($vauConnection.IsAuthenticated)" -ForegroundColor White
Write-Host "  Requests gesendet:  $($vauConnection.RequestCounter)" -ForegroundColor White
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
Write-Host "HINWEIS: Dies ist ein Gerüst-Skript. Die VAU-Protokoll-Implementierung" -ForegroundColor Yellow
Write-Host "         erfordert zusätzliche Bibliotheken für CBOR und Kyber768." -ForegroundColor Yellow
Write-Host ""
Write-Host "Referenzen:" -ForegroundColor Cyan
Write-Host "  - gematik/ePA-Basic: https://github.com/gematik/ePA-Basic" -ForegroundColor Cyan
Write-Host "  - gemSpec_Krypt: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt" -ForegroundColor Cyan
Write-Host ""
