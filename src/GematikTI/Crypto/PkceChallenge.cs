using System.Security.Cryptography;
using System.Text;

namespace GematikTI.Crypto;

/// <summary>
/// PKCE (Proof Key for Code Exchange) Implementation gemaess RFC 7636
/// </summary>
public class PkceChallenge
{
    /// <summary>
    /// Code Verifier (43-128 Zeichen)
    /// </summary>
    public string Verifier { get; }
    
    /// <summary>
    /// Code Challenge (SHA256 Hash des Verifiers)
    /// </summary>
    public string Challenge { get; }
    
    /// <summary>
    /// Challenge Method (immer S256)
    /// </summary>
    public string Method => "S256";
    
    public PkceChallenge()
    {
        // Code Verifier: 32 zufaellige Bytes, Base64URL-kodiert
        var verifierBytes = RandomNumberGenerator.GetBytes(32);
        Verifier = Base64UrlEncode(verifierBytes);
        
        // Code Challenge: SHA256(code_verifier), Base64URL-kodiert
        var challengeHash = SHA256.HashData(Encoding.ASCII.GetBytes(Verifier));
        Challenge = Base64UrlEncode(challengeHash);
    }
    
    /// <summary>
    /// Base64URL-Kodierung (ohne Padding)
    /// </summary>
    public static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
    
    /// <summary>
    /// Base64URL-Dekodierung
    /// </summary>
    public static byte[] Base64UrlDecode(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
