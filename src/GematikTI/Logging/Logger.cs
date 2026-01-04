namespace GematikTI.Logging;

/// <summary>
/// Einfacher Konsolen-Logger mit farbiger Ausgabe
/// </summary>
public static class Logger
{
    public static bool VerboseLogging { get; set; } = true;
    
    public enum LogLevel
    {
        Debug,
        Info,
        Ok,
        Warn,
        Error
    }
    
    public static void Log(string message, LogLevel level = LogLevel.Info)
    {
        if (level == LogLevel.Debug && !VerboseLogging)
            return;
        
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        var levelStr = level.ToString().ToUpper();
        
        var color = level switch
        {
            LogLevel.Debug => ConsoleColor.Gray,
            LogLevel.Info => ConsoleColor.White,
            LogLevel.Ok => ConsoleColor.Green,
            LogLevel.Warn => ConsoleColor.Yellow,
            LogLevel.Error => ConsoleColor.Red,
            _ => ConsoleColor.White
        };
        
        var originalColor = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine($"[{timestamp}] [{levelStr}] {message}");
        Console.ForegroundColor = originalColor;
    }
    
    public static void Debug(string message) => Log(message, LogLevel.Debug);
    public static void Info(string message) => Log(message, LogLevel.Info);
    public static void Ok(string message) => Log(message, LogLevel.Ok);
    public static void Warn(string message) => Log(message, LogLevel.Warn);
    public static void Error(string message) => Log(message, LogLevel.Error);
    
    public static void Header(string title)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(new string('=', 76));
        Console.WriteLine($"  {title}");
        Console.WriteLine(new string('=', 76));
        Console.ResetColor();
        Console.WriteLine();
    }
    
    public static void Section(string title)
    {
        Console.WriteLine();
        Info($"=== {title} ===");
    }
    
    public static void Box(string title, ConsoleColor color = ConsoleColor.Cyan)
    {
        Console.WriteLine();
        Console.ForegroundColor = color;
        Console.WriteLine(new string('=', 76));
        Console.WriteLine($"  {title,-72}");
        Console.WriteLine(new string('=', 76));
        Console.ResetColor();
    }
    
    public static void ErrorBox(string title, IEnumerable<string> errors)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(new string('=', 76));
        Console.WriteLine($"  {title,-72}");
        Console.WriteLine(new string('=', 76));
        Console.ResetColor();
        
        foreach (var error in errors)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  X {error}");
            Console.ResetColor();
        }
        
        Console.WriteLine();
    }
}
