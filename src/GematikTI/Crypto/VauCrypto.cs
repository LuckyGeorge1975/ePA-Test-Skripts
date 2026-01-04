using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

namespace GematikTI.Crypto;

/// <summary>
/// VAU-Protokoll Kryptografie-Funktionen gemaess gemSpec_Krypt
/// </summary>
public static class VauCrypto
{
    private static readonly SecureRandom SecureRandom = new();

    #region Kyber768/ML-KEM-768

    /// <summary>
    /// Erzeugt ein Kyber768-Schluesselpaar
    /// </summary>
    public static (KyberPublicKeyParameters PublicKey, KyberPrivateKeyParameters PrivateKey, byte[] PublicKeyBytes) GenerateKyber768KeyPair()
    {
        var keyGenParams = new KyberKeyGenerationParameters(SecureRandom, KyberParameters.kyber768);
        var keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.Init(keyGenParams);
        
        var keyPair = keyPairGenerator.GenerateKeyPair();
        var publicKey = (KyberPublicKeyParameters)keyPair.Public;
        var privateKey = (KyberPrivateKeyParameters)keyPair.Private;
        
        return (publicKey, privateKey, publicKey.GetEncoded());
    }

    /// <summary>
    /// Fuehrt KEM-Encapsulation mit einem Kyber768-Schluessel durch
    /// </summary>
    public static (byte[] SharedSecret, byte[] Ciphertext) Kyber768Encapsulate(KyberPublicKeyParameters publicKey)
    {
        var kemGenerator = new KyberKemGenerator(SecureRandom);
        var encapsulatedSecret = kemGenerator.GenerateEncapsulated(publicKey);
        
        return (encapsulatedSecret.GetSecret(), encapsulatedSecret.GetEncapsulation());
    }

    /// <summary>
    /// Fuehrt KEM-Decapsulation mit einem Kyber768-Schluessel durch
    /// </summary>
    public static byte[] Kyber768Decapsulate(KyberPrivateKeyParameters privateKey, byte[] ciphertext)
    {
        var kemExtractor = new KyberKemExtractor(privateKey);
        return kemExtractor.ExtractSecret(ciphertext);
    }

    #endregion

    #region ECDH P-256

    /// <summary>
    /// Erzeugt ein ECDH-Schluesselpaar (P-256)
    /// </summary>
    public static (ECPublicKeyParameters PublicKey, ECPrivateKeyParameters PrivateKey, byte[] X, byte[] Y) GenerateEcdhKeyPair()
    {
        var ecParams = SecNamedCurves.GetByName("secp256r1");
        var ecDomainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);
        var ecKeyGenParams = new ECKeyGenerationParameters(ecDomainParams, SecureRandom);
        
        var keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.Init(ecKeyGenParams);
        var keyPair = keyPairGenerator.GenerateKeyPair();
        
        var publicKey = (ECPublicKeyParameters)keyPair.Public;
        var privateKey = (ECPrivateKeyParameters)keyPair.Private;
        
        // X und Y Koordinaten extrahieren (32 Byte, Big-Endian)
        var x = publicKey.Q.AffineXCoord.GetEncoded();
        var y = publicKey.Q.AffineYCoord.GetEncoded();
        
        return (publicKey, privateKey, x, y);
    }

    #endregion

    #region AES/GCM

    /// <summary>
    /// AES/GCM Verschluesselung mit AAD
    /// </summary>
    public static (byte[] Ciphertext, byte[] Tag) AesGcmEncrypt(byte[] key, byte[] iv, byte[] plaintext, byte[]? associatedData = null)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var aeadParams = new AeadParameters(new KeyParameter(key), 128, iv, associatedData ?? Array.Empty<byte>());
        
        cipher.Init(true, aeadParams);
        
        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);
        
        // Output enthaelt Ciphertext + Tag (letzte 16 Bytes)
        var ciphertext = output[..(output.Length - 16)];
        var tag = output[(output.Length - 16)..];
        
        return (ciphertext, tag);
    }

    /// <summary>
    /// AES/GCM Entschluesselung mit AAD
    /// </summary>
    public static byte[] AesGcmDecrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag, byte[]? associatedData = null)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var aeadParams = new AeadParameters(new KeyParameter(key), 128, iv, associatedData ?? Array.Empty<byte>());
        
        cipher.Init(false, aeadParams);
        
        // Ciphertext + Tag zusammenfuegen
        var input = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, input, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, input, ciphertext.Length, tag.Length);
        
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        len += cipher.DoFinal(output, len);
        
        return output[..len];
    }

    #endregion

    #region HKDF (RFC 5869)

    /// <summary>
    /// HKDF-Extract
    /// </summary>
    public static byte[] HkdfExtract(byte[]? salt, byte[] inputKeyMaterial)
    {
        salt ??= new byte[32]; // SHA-256 Hash-Laenge
        
        using var hmac = new HMACSHA256(salt);
        return hmac.ComputeHash(inputKeyMaterial);
    }

    /// <summary>
    /// HKDF-Expand
    /// </summary>
    public static byte[] HkdfExpand(byte[] prk, byte[]? info, int length)
    {
        info ??= Array.Empty<byte>();
        
        const int hashLen = 32; // SHA-256
        var n = (int)Math.Ceiling((double)length / hashLen);
        var okm = new List<byte>();
        var t = Array.Empty<byte>();
        
        for (var i = 1; i <= n; i++)
        {
            using var hmac = new HMACSHA256(prk);
            var input = new byte[t.Length + info.Length + 1];
            Buffer.BlockCopy(t, 0, input, 0, t.Length);
            Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
            input[^1] = (byte)i;
            
            t = hmac.ComputeHash(input);
            okm.AddRange(t);
        }
        
        return okm.Take(length).ToArray();
    }

    /// <summary>
    /// HKDF (Extract + Expand)
    /// </summary>
    public static byte[] Hkdf(byte[] inputKeyMaterial, byte[]? salt = null, byte[]? info = null, int length = 64)
    {
        var prk = HkdfExtract(salt, inputKeyMaterial);
        return HkdfExpand(prk, info, length);
    }

    #endregion

    #region Hilfsfunktionen

    /// <summary>
    /// Erzeugt zufaellige Bytes
    /// </summary>
    public static byte[] GetRandomBytes(int length)
    {
        return RandomNumberGenerator.GetBytes(length);
    }

    /// <summary>
    /// SHA-256 Hash
    /// </summary>
    public static byte[] Sha256(byte[] data)
    {
        return SHA256.HashData(data);
    }

    #endregion
}
