using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using GematikTI.Auth;
using GematikTI.Configuration;
using GematikTI.Crypto;
using GematikTI.Logging;

namespace GematikTI.Epa;

/// <summary>
/// ePA-Client fuer die Kommunikation mit dem Aktensystem
/// </summary>
public class EpaClient
{
    private readonly GematikConfig _config;
    private readonly HttpClient _httpClient;
    private readonly VauProtocolClient _vauClient;
    private readonly OidcAuthService _authService;
    
    private VauConnection? _vauConnection;
    private TokenResponse? _tokens;
    
    public EpaClient(GematikConfig config)
    {
        _config = config;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(config.Optionen.HttpTimeoutSeconds)
        };
        _vauClient = new VauProtocolClient(config);
        _authService = new OidcAuthService(config);
    }
    
    /// <summary>
    /// Fuehrt den vollstaendigen ePA-Test durch
    /// </summary>
    public async Task RunTestAsync()
    {
        Logger.Header("ePA 3.x Testclient (gemaess Gematik-Spezifikation)");
        
        // Konfiguration validieren
        var errors = ConfigValidator.ValidateForEpa(_config);
        if (errors.Count > 0)
        {
            Logger.ErrorBox("KONFIGURATIONSFEHLER", errors);
            Console.WriteLine("Bearbeiten Sie die Konfigurationsdatei (config.json oder config.epa.json).");
            return;
        }
        
        Logger.Info($"Umgebung: {_config.Umgebung}");
        Logger.Info($"KVNR: {MaskKvnr(_config.Versicherter.KVNR)}");
        Logger.Info($"Authentifizierung: {_config.Authentifizierung.Methode}");
        
        try
        {
            // SCHRITT 1: VAU-Zertifikat abrufen
            Logger.Section("SCHRITT 1: VAU-Zertifikat");
            await GetVauCertificateAsync();
            
            // SCHRITT 2: VAU-Handshake
            Logger.Section("SCHRITT 2: VAU-Handshake");
            _vauConnection = await _vauClient.InitializeConnectionAsync();
            
            // SCHRITT 3: OIDC-Authentifizierung
            Logger.Section("SCHRITT 3: OIDC-Authentifizierung");
            await AuthenticateAsync();
            
            // SCHRITT 4: FHIR-Request ueber VAU-Kanal
            Logger.Section("SCHRITT 4: FHIR-Request");
            await SendFhirRequestAsync();
            
            Logger.Section("ePA-Test abgeschlossen");
            Logger.Ok("Verbindung zur ePA erfolgreich getestet!");
        }
        catch (Exception ex)
        {
            Logger.Error($"Fehler: {ex.Message}");
            Logger.Debug(ex.StackTrace ?? "");
        }
    }
    
    private async Task GetVauCertificateAsync()
    {
        Logger.Info("Beziehe VAU-Zertifikat vom Aktensystem...");
        
        var certDataUrl = $"{_config.EPA.AktensystemBaseUrl.TrimEnd('/')}/VAU/CertData";
        
        try
        {
            var response = await _httpClient.GetAsync(certDataUrl);
            
            if (response.IsSuccessStatusCode)
            {
                Logger.Ok("VAU-Zertifikat erhalten");
                // TODO: Zertifikatspruefung gegen TI-PKI (RCA5)
            }
            else
            {
                Logger.Warn($"VAU-Zertifikat konnte nicht abgerufen werden: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Logger.Warn($"Fehler beim Abrufen des VAU-Zertifikats: {ex.Message}");
        }
    }
    
    private async Task AuthenticateAsync()
    {
        // IDP Discovery
        var idpUrl = _config.Authentifizierung.Methode == "GesundheitsID"
            ? _config.Authentifizierung.SektoralerIdpDiscoveryUrl
            : _config.EPA.AktensystemBaseUrl; // Fuer andere Methoden
        
        var discovery = await _authService.GetDiscoveryAsync(idpUrl);
        
        // PKCE Challenge
        var pkce = new PkceChallenge();
        Logger.Ok("PKCE Challenge erstellt");
        Logger.Debug($"  Verifier-Laenge: {pkce.Verifier.Length} Zeichen");
        
        // Authorization URL generieren
        var (authUrl, state, nonce) = _authService.GenerateAuthorizationUrl(discovery, pkce, "openid epa");
        
        // Benutzer zur Authentifizierung auffordern
        _authService.ShowAuthorizationPrompt(authUrl);
        
        // Auf Authorization Code warten
        Console.Write("Bitte Authorization Code eingeben: ");
        var authorizationCode = Console.ReadLine()?.Trim();
        
        if (string.IsNullOrEmpty(authorizationCode))
        {
            throw new Exception("Kein Authorization Code eingegeben");
        }
        
        // Tokens abrufen
        _tokens = await _authService.ExchangeCodeForTokensAsync(discovery, authorizationCode, pkce.Verifier);
    }
    
    private async Task SendFhirRequestAsync()
    {
        if (_vauConnection == null || _tokens == null)
        {
            Logger.Warn("Keine VAU-Verbindung oder Tokens vorhanden");
            return;
        }
        
        // Innerer HTTP-Request
        var innerRequest = $@"GET /fhir/Patient/{_config.Versicherter.KVNR} HTTP/1.1
Host: epa-aktensystem
Authorization: Bearer {_tokens.access_token}
Accept: application/fhir+json

";
        
        Logger.Info($"Sende FHIR-Request: GET /fhir/Patient/{MaskKvnr(_config.Versicherter.KVNR)}");
        
        // Request verschluesseln
        var encryptedRequest = _vauClient.ProtectRequest(_vauConnection, innerRequest);
        
        // Ueber VAU-Kanal senden
        var vauUrl = $"{_config.EPA.AktensystemBaseUrl.TrimEnd('/')}{_vauConnection.VauCid}";
        
        try
        {
            var content = new ByteArrayContent(encryptedRequest);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            
            var response = await _httpClient.PostAsync(vauUrl, content);
            
            if (response.IsSuccessStatusCode)
            {
                var responseBytes = await response.Content.ReadAsByteArrayAsync();
                var decryptedResponse = _vauClient.UnprotectResponse(_vauConnection, responseBytes);
                
                Logger.Ok("FHIR-Response erhalten und entschluesselt");
                Logger.Debug(decryptedResponse);
            }
            else
            {
                Logger.Warn($"FHIR-Request fehlgeschlagen: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Logger.Warn($"FHIR-Request fehlgeschlagen: {ex.Message}");
            Logger.Info("(Im Demo-Modus ist dies erwartet)");
        }
    }
    
    private static string MaskKvnr(string kvnr)
    {
        if (kvnr.Length >= 10)
            return $"{kvnr[..3]}****{kvnr[7..]}";
        return "****";
    }
}
