using System.CommandLine;
using System.Text.Json;
using GematikTI.Configuration;
using GematikTI.Epa;
using GematikTI.ERezept;
using GematikTI.Logging;

namespace GematikTI;

/// <summary>
/// Gematik TI Test-Client - Hauptprogramm
/// 
/// Verwendung:
///   GematikTI epa [--config config.epa.json]
///   GematikTI erezept [--config config.erezept.json]
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        // Root-Befehl
        var rootCommand = new RootCommand("Gematik Telematikinfrastruktur Test-Client fuer ePA und E-Rezept");
        
        // Globale Option fuer Konfigurationsdatei
        var configOption = new Option<FileInfo?>(
            aliases: new[] { "--config", "-c" },
            description: "Pfad zur Konfigurationsdatei (JSON)");
        
        // ePA-Unterbefehl
        var epaCommand = new Command("epa", "Teste Verbindung zur elektronischen Patientenakte (ePA 3.x)");
        epaCommand.AddOption(configOption);
        epaCommand.SetHandler(async (configFile) =>
        {
            await RunEpaTestAsync(configFile);
        }, configOption);
        
        // E-Rezept-Unterbefehl
        var erezeptCommand = new Command("erezept", "Pruefe E-Rezepte fuer einen Versicherten");
        erezeptCommand.AddOption(configOption);
        erezeptCommand.SetHandler(async (configFile) =>
        {
            await RunERezeptTestAsync(configFile);
        }, configOption);
        
        rootCommand.AddCommand(epaCommand);
        rootCommand.AddCommand(erezeptCommand);
        
        // Standardverhalten: Hilfe anzeigen
        if (args.Length == 0)
        {
            ShowWelcome();
            args = new[] { "--help" };
        }
        
        return await rootCommand.InvokeAsync(args);
    }
    
    static void ShowWelcome()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("  ╔═══════════════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║       Gematik Telematikinfrastruktur (TI) Test-Client                 ║");
        Console.WriteLine("  ║                                                                       ║");
        Console.WriteLine("  ║       ePA 3.x  |  E-Rezept  |  gemaess Gematik-Spezifikation          ║");
        Console.WriteLine("  ╚═══════════════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();
    }
    
    static async Task RunEpaTestAsync(FileInfo? configFile)
    {
        try
        {
            var config = await LoadConfigAsync(configFile, "config.epa.json");
            Logger.VerboseLogging = config.Optionen.VerboseLogging;
            
            var client = new EpaClient(config);
            await client.RunTestAsync();
        }
        catch (Exception ex)
        {
            Logger.Error($"Fehler beim Ausfuehren des ePA-Tests: {ex.Message}");
            Environment.ExitCode = 1;
        }
    }
    
    static async Task RunERezeptTestAsync(FileInfo? configFile)
    {
        try
        {
            var config = await LoadConfigAsync(configFile, "config.erezept.json");
            Logger.VerboseLogging = config.Optionen.VerboseLogging;
            
            var client = new ERezeptClient(config);
            await client.RunTestAsync();
        }
        catch (Exception ex)
        {
            Logger.Error($"Fehler beim Ausfuehren des E-Rezept-Tests: {ex.Message}");
            Environment.ExitCode = 1;
        }
    }
    
    static async Task<GematikConfig> LoadConfigAsync(FileInfo? configFile, string defaultFileName)
    {
        // Konfigurationsdatei suchen
        var configPaths = new List<string>();
        
        if (configFile != null)
        {
            configPaths.Add(configFile.FullName);
        }
        else
        {
            // Standardpfade
            configPaths.Add(defaultFileName);
            configPaths.Add("config.json");
            configPaths.Add(Path.Combine(AppContext.BaseDirectory, defaultFileName));
            configPaths.Add(Path.Combine(AppContext.BaseDirectory, "config.json"));
        }
        
        string? configPath = null;
        foreach (var path in configPaths)
        {
            if (File.Exists(path))
            {
                configPath = path;
                break;
            }
        }
        
        if (configPath == null)
        {
            Logger.Warn($"Keine Konfigurationsdatei gefunden. Erstelle Beispiel: {defaultFileName}");
            await CreateSampleConfigAsync(defaultFileName);
            throw new FileNotFoundException($"Bitte konfigurieren Sie die Datei '{defaultFileName}' und starten Sie erneut.");
        }
        
        Logger.Info($"Lade Konfiguration aus: {configPath}");
        
        var jsonContent = await File.ReadAllTextAsync(configPath);
        
        // Kommentare entfernen (Properties die mit "//" beginnen)
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };
        
        var config = JsonSerializer.Deserialize<GematikConfig>(jsonContent, options);
        
        if (config == null)
        {
            throw new Exception("Konfiguration konnte nicht geladen werden");
        }
        
        return config;
    }
    
    static async Task CreateSampleConfigAsync(string fileName)
    {
        var sampleConfig = new GematikConfig
        {
            Umgebung = "RU",
            EPA = new EpaConfig
            {
                AktensystemBaseUrl = "https://epa.beispiel.de"
            },
            ERezept = new ERezeptConfig
            {
                FdBaseUrl = "https://erp-ref.zentral.erp.splitdns.ti-dienste.de",
                IdpBaseUrl = "https://idp-ref.zentral.idp.splitdns.ti-dienste.de"
            },
            Authentifizierung = new AuthConfig
            {
                Methode = "GesundheitsID",
                OidcClientId = "IHRE_CLIENT_ID",
                OidcRedirectUri = "http://localhost:8888/callback",
                SektoralerIdpDiscoveryUrl = "https://idp.ihrer-krankenkasse.de/.well-known/openid-configuration"
            },
            Versicherter = new VersicherterConfig
            {
                KVNR = "X123456789"
            },
            Optionen = new OptionsConfig
            {
                HttpTimeoutSeconds = 30,
                VerboseLogging = true,
                LocalRedirectPort = 8888,
                FhirVersion = "4.0.1",
                MaxRezepte = 50,
                RezeptStatus = new[] { "ready", "in-progress" }
            }
        };
        
        var options = new JsonSerializerOptions
        {
            WriteIndented = true
        };
        
        var json = JsonSerializer.Serialize(sampleConfig, options);
        await File.WriteAllTextAsync(fileName, json);
        
        Logger.Info($"Beispiel-Konfiguration erstellt: {fileName}");
    }
}
