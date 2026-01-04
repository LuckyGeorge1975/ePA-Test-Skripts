using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using GematikTI.Configuration;
using GematikTI.Crypto;
using GematikTI.Logging;

namespace GematikTI.Auth;

/// <summary>
/// OIDC Discovery Dokument
/// </summary>
public class OidcDiscovery
{
    public string authorization_endpoint { get; set; } = "";
    public string token_endpoint { get; set; } = "";
    public string userinfo_endpoint { get; set; } = "";
    public string jwks_uri { get; set; } = "";
    public string issuer { get; set; } = "";
}

/// <summary>
/// OIDC Token Response
/// </summary>
public class TokenResponse
{
    public string access_token { get; set; } = "";
    public string token_type { get; set; } = "";
    public int expires_in { get; set; }
    public string? refresh_token { get; set; }
    public string? id_token { get; set; }
    public string? scope { get; set; }
}

/// <summary>
/// OIDC/PKCE Authentifizierungs-Service
/// </summary>
public class OidcAuthService
{
    private readonly HttpClient _httpClient;
    private readonly GematikConfig _config;
    
    public OidcAuthService(GematikConfig config)
    {
        _config = config;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(config.Optionen.HttpTimeoutSeconds)
        };
    }
    
    /// <summary>
    /// Ruft das OIDC Discovery-Dokument ab
    /// </summary>
    public async Task<OidcDiscovery> GetDiscoveryAsync(string baseUrl)
    {
        Logger.Info("Rufe IDP Discovery-Dokument ab...");
        
        var discoveryUrl = baseUrl.TrimEnd('/');
        if (!discoveryUrl.EndsWith("/.well-known/openid-configuration"))
        {
            discoveryUrl += "/.well-known/openid-configuration";
        }
        
        try
        {
            var response = await _httpClient.GetStringAsync(discoveryUrl);
            var discovery = JsonSerializer.Deserialize<OidcDiscovery>(response)
                ?? throw new Exception("Discovery-Dokument konnte nicht deserialisiert werden");
            
            Logger.Ok("IDP Discovery erfolgreich");
            Logger.Debug($"  Authorization Endpoint: {discovery.authorization_endpoint}");
            Logger.Debug($"  Token Endpoint: {discovery.token_endpoint}");
            
            return discovery;
        }
        catch (Exception ex)
        {
            Logger.Error($"Fehler beim Abrufen der IDP Discovery: {ex.Message}");
            throw;
        }
    }
    
    /// <summary>
    /// Generiert die Authorization-URL fuer den OIDC-Flow
    /// </summary>
    public (string AuthorizationUrl, string State, string Nonce) GenerateAuthorizationUrl(
        OidcDiscovery discovery,
        PkceChallenge pkce,
        string scope = "openid e-rezept")
    {
        Logger.Info("Generiere Authorization-URL...");
        
        var state = PkceChallenge.Base64UrlEncode(VauCrypto.GetRandomBytes(16));
        var nonce = PkceChallenge.Base64UrlEncode(VauCrypto.GetRandomBytes(16));
        
        var queryParams = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = _config.Authentifizierung.OidcClientId,
            ["redirect_uri"] = _config.Authentifizierung.OidcRedirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = pkce.Challenge,
            ["code_challenge_method"] = pkce.Method
        };
        
        var queryString = string.Join("&", queryParams.Select(
            kvp => $"{kvp.Key}={HttpUtility.UrlEncode(kvp.Value)}"));
        
        var authorizationUrl = $"{discovery.authorization_endpoint}?{queryString}";
        
        Logger.Ok("Authorization URL generiert");
        
        return (authorizationUrl, state, nonce);
    }
    
    /// <summary>
    /// Zeigt die Authorization-URL an und fordert zur manuellen Authentifizierung auf
    /// </summary>
    public void ShowAuthorizationPrompt(string authorizationUrl)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(new string('=', 76));
        Console.WriteLine("  MANUELLE AUTHENTIFIZIERUNG ERFORDERLICH");
        Console.WriteLine(new string('=', 76));
        Console.ResetColor();
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("Bitte oeffnen Sie folgende URL in Ihrem Browser:");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine(authorizationUrl);
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("Nach erfolgreicher Authentifizierung werden Sie zu einer lokalen URL");
        Console.WriteLine("weitergeleitet. Kopieren Sie den 'code'-Parameter aus der URL.");
        Console.ResetColor();
        Console.WriteLine();
    }
    
    /// <summary>
    /// Tauscht den Authorization Code gegen Tokens
    /// </summary>
    public async Task<TokenResponse> ExchangeCodeForTokensAsync(
        OidcDiscovery discovery,
        string authorizationCode,
        string codeVerifier)
    {
        Logger.Info("Tausche Authorization Code gegen Tokens...");
        
        var tokenParams = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authorizationCode,
            ["redirect_uri"] = _config.Authentifizierung.OidcRedirectUri,
            ["client_id"] = _config.Authentifizierung.OidcClientId,
            ["code_verifier"] = codeVerifier
        };
        
        try
        {
            var content = new FormUrlEncodedContent(tokenParams);
            var response = await _httpClient.PostAsync(discovery.token_endpoint, content);
            
            response.EnsureSuccessStatusCode();
            
            var responseBody = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseBody)
                ?? throw new Exception("Token-Response konnte nicht deserialisiert werden");
            
            Logger.Ok("Tokens erfolgreich erhalten");
            Logger.Debug($"  Token-Typ: {tokenResponse.token_type}");
            Logger.Debug($"  Gueltig fuer: {tokenResponse.expires_in} Sekunden");
            
            return tokenResponse;
        }
        catch (Exception ex)
        {
            Logger.Error($"Fehler beim Token-Austausch: {ex.Message}");
            throw;
        }
    }
}
