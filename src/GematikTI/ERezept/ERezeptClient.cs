using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using GematikTI.Auth;
using GematikTI.Configuration;
using GematikTI.Crypto;
using GematikTI.Logging;

namespace GematikTI.ERezept;

#region FHIR Models

/// <summary>
/// FHIR Bundle
/// </summary>
public class FhirBundle
{
    [JsonPropertyName("resourceType")]
    public string ResourceType { get; set; } = "Bundle";
    
    [JsonPropertyName("type")]
    public string Type { get; set; } = "";
    
    [JsonPropertyName("total")]
    public int? Total { get; set; }
    
    [JsonPropertyName("entry")]
    public List<BundleEntry>? Entry { get; set; }
}

/// <summary>
/// FHIR Bundle Entry
/// </summary>
public class BundleEntry
{
    [JsonPropertyName("fullUrl")]
    public string? FullUrl { get; set; }
    
    [JsonPropertyName("resource")]
    public TaskResource? Resource { get; set; }
}

/// <summary>
/// FHIR Task Resource
/// </summary>
public class TaskResource
{
    [JsonPropertyName("resourceType")]
    public string ResourceType { get; set; } = "";
    
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    
    [JsonPropertyName("status")]
    public string? Status { get; set; }
    
    [JsonPropertyName("authoredOn")]
    public string? AuthoredOn { get; set; }
    
    [JsonPropertyName("identifier")]
    public List<Identifier>? Identifier { get; set; }
    
    [JsonPropertyName("extension")]
    public List<Extension>? Extension { get; set; }
}

public class Identifier
{
    [JsonPropertyName("system")]
    public string? System { get; set; }
    
    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

public class Extension
{
    [JsonPropertyName("url")]
    public string? Url { get; set; }
    
    [JsonPropertyName("valueCoding")]
    public Coding? ValueCoding { get; set; }
}

public class Coding
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }
    
    [JsonPropertyName("display")]
    public string? Display { get; set; }
}

#endregion

/// <summary>
/// E-Rezept-Client fuer die Kommunikation mit dem E-Rezept-Fachdienst
/// </summary>
public class ERezeptClient
{
    private readonly GematikConfig _config;
    private readonly HttpClient _httpClient;
    private readonly OidcAuthService _authService;
    
    private TokenResponse? _tokens;
    
    public ERezeptClient(GematikConfig config)
    {
        _config = config;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(config.Optionen.HttpTimeoutSeconds)
        };
        _authService = new OidcAuthService(config);
    }
    
    /// <summary>
    /// Fuehrt den vollstaendigen E-Rezept-Test durch
    /// </summary>
    public async Task RunTestAsync()
    {
        Logger.Header("E-Rezept Testclient (gemaess Gematik-Spezifikation)");
        
        // Konfiguration validieren
        var errors = ConfigValidator.ValidateForERezept(_config);
        if (errors.Count > 0)
        {
            Logger.ErrorBox("KONFIGURATIONSFEHLER", errors);
            Console.WriteLine("Bearbeiten Sie die Konfigurationsdatei (config.json oder config.erezept.json).");
            return;
        }
        
        Logger.Info($"Umgebung: {_config.Umgebung}");
        Logger.Info($"KVNR: {MaskKvnr(_config.Versicherter.KVNR)}");
        Logger.Info($"Authentifizierung: {_config.Authentifizierung.Methode}");
        
        try
        {
            // SCHRITT 1: IDP Discovery
            Logger.Section("SCHRITT 1: IDP Discovery");
            var discovery = await GetIdpDiscoveryAsync();
            
            // SCHRITT 2: PKCE Challenge
            Logger.Section("SCHRITT 2: PKCE Challenge generieren");
            var pkce = new PkceChallenge();
            Logger.Ok("PKCE Challenge erstellt");
            Logger.Debug($"  Verifier-Laenge: {pkce.Verifier.Length} Zeichen");
            
            // SCHRITT 3: Authentifizierung
            Logger.Section("SCHRITT 3: Authentifizierung");
            await AuthenticateAsync(discovery, pkce);
            
            // SCHRITT 4: Tokens abrufen (nach manueller Eingabe)
            Logger.Section("SCHRITT 4: Tokens abrufen");
            // Token-Austausch erfolgt in AuthenticateAsync
            
            // SCHRITT 5: E-Rezepte abrufen
            Logger.Section("SCHRITT 5: E-Rezepte abrufen");
            var rezepte = await GetERezepteAsync();
            
            // SCHRITT 6: Ergebnisse anzeigen
            Logger.Section("SCHRITT 6: Ergebnisse");
            ShowERezepte(rezepte);
            
            // Optional: JSON-Export
            await ExportRezepteAsync(rezepte);
            
            Logger.Section("E-Rezept-Abfrage abgeschlossen");
            Logger.Ok("Verbindung zum E-Rezept-Fachdienst erfolgreich getestet!");
        }
        catch (Exception ex)
        {
            Logger.Error($"Fehler: {ex.Message}");
            Logger.Debug(ex.StackTrace ?? "");
        }
    }
    
    private async Task<OidcDiscovery> GetIdpDiscoveryAsync()
    {
        var idpUrl = _config.Authentifizierung.Methode == "GesundheitsID"
            ? _config.Authentifizierung.SektoralerIdpDiscoveryUrl
            : _config.ERezept.IdpBaseUrl;
        
        return await _authService.GetDiscoveryAsync(idpUrl);
    }
    
    private async Task AuthenticateAsync(OidcDiscovery discovery, PkceChallenge pkce)
    {
        // Authorization URL generieren
        var (authUrl, state, nonce) = _authService.GenerateAuthorizationUrl(discovery, pkce, "openid e-rezept");
        
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
    
    private async Task<FhirBundle?> GetERezepteAsync()
    {
        if (_tokens == null)
        {
            throw new Exception("Keine Tokens vorhanden");
        }
        
        Logger.Info("Rufe E-Rezepte ab...");
        
        // FHIR Task-Suche aufbauen
        var searchParams = new List<string>();
        
        // Status-Filter
        foreach (var status in _config.Optionen.RezeptStatus)
        {
            searchParams.Add($"status={status}");
        }
        
        // Anzahl begrenzen
        searchParams.Add($"_count={_config.Optionen.MaxRezepte}");
        
        // Sortierung (neueste zuerst)
        searchParams.Add("_sort=-authored-on");
        
        var queryString = string.Join("&", searchParams);
        var taskUrl = $"{_config.ERezept.FdBaseUrl.TrimEnd('/')}/Task?{queryString}";
        
        Logger.Debug($"  URL: {taskUrl}");
        
        var request = new HttpRequestMessage(HttpMethod.Get, taskUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _tokens.access_token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue($"application/fhir+json"));
        request.Headers.Add("X-Request-Id", Guid.NewGuid().ToString());
        
        try
        {
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            
            var content = await response.Content.ReadAsStringAsync();
            var bundle = JsonSerializer.Deserialize<FhirBundle>(content);
            
            Logger.Ok("E-Rezepte erfolgreich abgerufen");
            
            return bundle;
        }
        catch (Exception ex)
        {
            Logger.Error($"Fehler beim Abrufen der E-Rezepte: {ex.Message}");
            throw;
        }
    }
    
    private void ShowERezepte(FhirBundle? bundle)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(new string('=', 76));
        Console.WriteLine("                         E-REZEPT UEBERSICHT");
        Console.WriteLine(new string('=', 76));
        Console.ResetColor();
        Console.WriteLine();
        
        if (bundle?.Entry == null || bundle.Entry.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  Keine E-Rezepte gefunden.");
            Console.ResetColor();
            Console.WriteLine();
            return;
        }
        
        var totalRezepte = bundle.Total ?? bundle.Entry.Count;
        Console.WriteLine($"  Gefundene E-Rezepte: {totalRezepte}");
        Console.WriteLine();
        
        var index = 1;
        foreach (var entry in bundle.Entry)
        {
            var task = entry.Resource;
            if (task?.ResourceType != "Task") continue;
            
            // Task-Informationen
            var taskId = task.Id ?? "Unbekannt";
            var status = task.Status ?? "Unbekannt";
            var authoredOn = "Unbekannt";
            
            if (DateTime.TryParse(task.AuthoredOn, out var date))
            {
                authoredOn = date.ToString("dd.MM.yyyy HH:mm");
            }
            
            // Rezept-Typ ermitteln
            var flowType = "Unbekannt";
            var flowTypeExt = task.Extension?.FirstOrDefault(e => 
                e.Url?.Contains("flowType") == true || e.Url?.Contains("PrescriptionType") == true);
            
            if (flowTypeExt?.ValueCoding?.Code != null)
            {
                flowType = flowTypeExt.ValueCoding.Code switch
                {
                    "160" => "Muster 16 (Apothekenpflichtig)",
                    "169" => "Muster 16 (Direktzuweisung)",
                    "200" => "PKV",
                    "209" => "PKV (Direktzuweisung)",
                    _ => flowTypeExt.ValueCoding.Code
                };
            }
            
            // AccessCode und PrescriptionId extrahieren
            var accessCode = task.Identifier?.FirstOrDefault(i => 
                i.System?.Contains("AccessCode") == true || i.System?.Contains("access-code") == true)?.Value;
            
            var prescriptionId = task.Identifier?.FirstOrDefault(i => 
                i.System?.Contains("PrescriptionID") == true || i.System?.Contains("prescription-id") == true)?.Value;
            
            // Status-Farbe
            var statusColor = status switch
            {
                "ready" => ConsoleColor.Green,
                "in-progress" => ConsoleColor.Yellow,
                "completed" => ConsoleColor.Gray,
                "cancelled" => ConsoleColor.Red,
                _ => ConsoleColor.White
            };
            
            // Ausgabe
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  +-------------------------------------------------------------------------+");
            Console.ResetColor();
            Console.Write("  | ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"Rezept #{index}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("                                                              |");
            Console.WriteLine("  +-------------------------------------------------------------------------+");
            Console.ResetColor();
            
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("  |  Task-ID:        ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(taskId);
            
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("  |  Status:         ");
            Console.ForegroundColor = statusColor;
            Console.WriteLine(status);
            
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("  |  Rezept-Typ:     ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(flowType);
            
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("  |  Ausgestellt am: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(authoredOn);
            
            if (!string.IsNullOrEmpty(prescriptionId))
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.Write("  |  Rezept-Nr:      ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(prescriptionId);
            }
            
            if (!string.IsNullOrEmpty(accessCode) && status == "ready")
            {
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.Write("  |  AccessCode:     ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"{accessCode[..Math.Min(20, accessCode.Length)]}...");
            }
            
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  +-------------------------------------------------------------------------+");
            Console.ResetColor();
            Console.WriteLine();
            
            index++;
        }
        
        // Zusammenfassung
        var readyCount = bundle.Entry.Count(e => e.Resource?.Status == "ready");
        var inProgressCount = bundle.Entry.Count(e => e.Resource?.Status == "in-progress");
        
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  -------------------------------------------------------------------------");
        Console.ResetColor();
        Console.WriteLine("  Zusammenfassung:");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"    Einloesbar (ready):      {readyCount}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"    In Bearbeitung:          {inProgressCount}");
        Console.ResetColor();
        Console.WriteLine();
    }
    
    private async Task ExportRezepteAsync(FhirBundle? bundle)
    {
        if (bundle == null) return;
        
        var outputFile = $"erezepte_export_{DateTime.Now:yyyyMMdd_HHmmss}.json";
        var json = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(outputFile, json);
        
        Logger.Ok($"Ergebnisse gespeichert in: {outputFile}");
    }
    
    private static string MaskKvnr(string kvnr)
    {
        if (kvnr.Length >= 10)
            return $"{kvnr[..3]}****{kvnr[7..]}";
        return "****";
    }
}
