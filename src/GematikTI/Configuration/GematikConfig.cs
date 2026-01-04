using System.Text.Json.Serialization;

namespace GematikTI.Configuration;

/// <summary>
/// Hauptkonfiguration fuer den Gematik TI Client
/// </summary>
public class GematikConfig
{
    /// <summary>
    /// Umgebung: RU (Referenz), TU (Test), PU (Produktion)
    /// </summary>
    public string Umgebung { get; set; } = "RU";
    
    /// <summary>
    /// ePA-spezifische Konfiguration
    /// </summary>
    public EpaConfig EPA { get; set; } = new();
    
    /// <summary>
    /// E-Rezept-spezifische Konfiguration
    /// </summary>
    public ERezeptConfig ERezept { get; set; } = new();
    
    /// <summary>
    /// Authentifizierungskonfiguration
    /// </summary>
    public AuthConfig Authentifizierung { get; set; } = new();
    
    /// <summary>
    /// Versichertendaten
    /// </summary>
    public VersicherterConfig Versicherter { get; set; } = new();
    
    /// <summary>
    /// Optionale Einstellungen
    /// </summary>
    public OptionsConfig Optionen { get; set; } = new();
}

/// <summary>
/// ePA-Konfiguration
/// </summary>
public class EpaConfig
{
    /// <summary>
    /// Basis-URL des ePA-Aktensystems (z.B. https://epa.ibm-gesundheit.de)
    /// </summary>
    public string AktensystemBaseUrl { get; set; } = "";
}

/// <summary>
/// E-Rezept-Konfiguration
/// </summary>
public class ERezeptConfig
{
    /// <summary>
    /// Basis-URL des E-Rezept-Fachdienstes
    /// </summary>
    public string FdBaseUrl { get; set; } = "";
    
    /// <summary>
    /// Basis-URL des zentralen IDP
    /// </summary>
    public string IdpBaseUrl { get; set; } = "";
}

/// <summary>
/// Authentifizierungskonfiguration
/// </summary>
public class AuthConfig
{
    /// <summary>
    /// Authentifizierungsmethode: GesundheitsID, eGK, SMC-B
    /// </summary>
    public string Methode { get; set; } = "GesundheitsID";
    
    /// <summary>
    /// OIDC Client-ID
    /// </summary>
    public string OidcClientId { get; set; } = "";
    
    /// <summary>
    /// OIDC Redirect-URI
    /// </summary>
    public string OidcRedirectUri { get; set; } = "http://localhost:8888/callback";
    
    /// <summary>
    /// Discovery-URL des sektoralen IDP (fuer GesundheitsID)
    /// </summary>
    public string SektoralerIdpDiscoveryUrl { get; set; } = "";
    
    /// <summary>
    /// Konnektor-URL (fuer eGK-Authentifizierung)
    /// </summary>
    public string KonnektorUrl { get; set; } = "";
    
    /// <summary>
    /// CardHandle der eGK
    /// </summary>
    public string EgkCardHandle { get; set; } = "";
}

/// <summary>
/// Versichertendaten
/// </summary>
public class VersicherterConfig
{
    /// <summary>
    /// Krankenversichertennummer (10-stellig: Buchstabe + 9 Ziffern)
    /// </summary>
    public string KVNR { get; set; } = "";
}

/// <summary>
/// Optionale Einstellungen
/// </summary>
public class OptionsConfig
{
    /// <summary>
    /// HTTP-Timeout in Sekunden
    /// </summary>
    public int HttpTimeoutSeconds { get; set; } = 30;
    
    /// <summary>
    /// Ausfuehrliche Protokollierung
    /// </summary>
    public bool VerboseLogging { get; set; } = true;
    
    /// <summary>
    /// Lokaler Port fuer OAuth Redirect
    /// </summary>
    public int LocalRedirectPort { get; set; } = 8888;
    
    /// <summary>
    /// FHIR-Version
    /// </summary>
    public string FhirVersion { get; set; } = "4.0.1";
    
    /// <summary>
    /// Maximale Anzahl abzurufender Rezepte
    /// </summary>
    public int MaxRezepte { get; set; } = 50;
    
    /// <summary>
    /// Rezept-Status Filter
    /// </summary>
    public string[] RezeptStatus { get; set; } = new[] { "ready", "in-progress" };
}

/// <summary>
/// Konfigurationsvalidierung
/// </summary>
public static class ConfigValidator
{
    public static List<string> ValidateForEpa(GematikConfig config)
    {
        var errors = new List<string>();
        
        if (string.IsNullOrWhiteSpace(config.EPA.AktensystemBaseUrl))
            errors.Add("ePA.AktensystemBaseUrl nicht konfiguriert");
        
        ValidateCommon(config, errors);
        
        return errors;
    }
    
    public static List<string> ValidateForERezept(GematikConfig config)
    {
        var errors = new List<string>();
        
        if (string.IsNullOrWhiteSpace(config.ERezept.FdBaseUrl))
            errors.Add("ERezept.FdBaseUrl nicht konfiguriert");
        
        if (string.IsNullOrWhiteSpace(config.ERezept.IdpBaseUrl))
            errors.Add("ERezept.IdpBaseUrl nicht konfiguriert");
        
        ValidateCommon(config, errors);
        
        return errors;
    }
    
    private static void ValidateCommon(GematikConfig config, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(config.Authentifizierung.OidcClientId))
            errors.Add("Authentifizierung.OidcClientId nicht konfiguriert");
        
        if (string.IsNullOrWhiteSpace(config.Versicherter.KVNR))
        {
            errors.Add("Versicherter.KVNR nicht konfiguriert");
        }
        else if (!System.Text.RegularExpressions.Regex.IsMatch(config.Versicherter.KVNR, @"^[A-Z][0-9]{9}$"))
        {
            errors.Add("Versicherter.KVNR hat ungueltiges Format (erwartet: Buchstabe + 9 Ziffern)");
        }
        
        if (config.Authentifizierung.Methode == "GesundheitsID")
        {
            if (string.IsNullOrWhiteSpace(config.Authentifizierung.SektoralerIdpDiscoveryUrl))
                errors.Add("Authentifizierung.SektoralerIdpDiscoveryUrl nicht konfiguriert (erforderlich fuer GesundheitsID)");
        }
        else if (config.Authentifizierung.Methode == "eGK")
        {
            if (string.IsNullOrWhiteSpace(config.Authentifizierung.KonnektorUrl))
                errors.Add("Authentifizierung.KonnektorUrl nicht konfiguriert (erforderlich fuer eGK)");
        }
    }
}
