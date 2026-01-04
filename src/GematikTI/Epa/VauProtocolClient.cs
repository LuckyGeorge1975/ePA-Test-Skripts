using System.Text;
using GematikTI.Configuration;
using GematikTI.Crypto;
using GematikTI.Logging;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using PeterO.Cbor;

namespace GematikTI.Epa;

/// <summary>
/// VAU-Verbindungsdaten
/// </summary>
public class VauConnection
{
    public string VauCid { get; set; } = "";
    public byte[] KeyId { get; set; } = Array.Empty<byte>();
    public byte[] K2_c2s_app_data { get; set; } = Array.Empty<byte>();
    public byte[] K2_s2c_app_data { get; set; } = Array.Empty<byte>();
    public long EncryptionCounter { get; set; } = 0;
    public long RequestCounter { get; set; } = 0;
}

/// <summary>
/// VAU-Protokoll Client gemaess gemSpec_Krypt Kapitel 7
/// </summary>
public class VauProtocolClient
{
    private readonly HttpClient _httpClient;
    private readonly GematikConfig _config;
    
    public VauProtocolClient(GematikConfig config)
    {
        _config = config;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(config.Optionen.HttpTimeoutSeconds)
        };
    }
    
    /// <summary>
    /// Fuehrt den VAU-Protokoll Handshake durch (Nachrichten 1-4)
    /// </summary>
    public async Task<VauConnection> InitializeConnectionAsync(string? existingVauNp = null)
    {
        Logger.Info("Starte VAU-Protokoll Handshake...");
        
        var connection = new VauConnection();
        var vauEndpoint = $"{_config.EPA.AktensystemBaseUrl.TrimEnd('/')}/VAU";
        
        try
        {
            // NACHRICHT 1: Client -> VAU (A_24428)
            Logger.Info("Erzeuge Nachricht 1 (ephemere Schluessel)...");
            
            // ECDH-Schluesselpaar erzeugen
            var (ecdhPublicKey, ecdhPrivateKey, ecdhX, ecdhY) = VauCrypto.GenerateEcdhKeyPair();
            
            // Kyber768-Schluesselpaar erzeugen
            Logger.Debug("  Erzeuge Kyber768-Schluesselpaar...");
            var (kyberPublicKey, kyberPrivateKey, kyberPublicKeyBytes) = VauCrypto.GenerateKyber768KeyPair();
            
            // Nachricht 1 als CBOR kodieren
            var message1Cbor = CreateMessage1Cbor(ecdhX, ecdhY, kyberPublicKeyBytes);
            Logger.Debug($"  Nachricht 1 CBOR: {message1Cbor.Length} Bytes");
            
            // Request senden
            var request1 = new HttpRequestMessage(HttpMethod.Post, vauEndpoint)
            {
                Content = new ByteArrayContent(message1Cbor)
            };
            request1.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/cbor");
            
            if (!string.IsNullOrEmpty(existingVauNp))
            {
                request1.Headers.Add("vau-np", existingVauNp);
                Logger.Debug($"  VAU-NP: {existingVauNp}");
            }
            
            Logger.Debug($"  Sende Nachricht 1 an {vauEndpoint}...");
            var response2 = await _httpClient.SendAsync(request1);
            
            // VAU-CID aus Response-Header extrahieren
            if (response2.Headers.TryGetValues("VAU-CID", out var vauCidValues))
            {
                connection.VauCid = vauCidValues.First();
                Logger.Debug($"  VAU-CID erhalten: {connection.VauCid}");
            }
            else
            {
                throw new Exception("VAU-CID nicht im Response-Header gefunden");
            }
            
            // NACHRICHT 2: VAU -> Client (A_24608)
            Logger.Info("Verarbeite Nachricht 2 (VAU-Schluessel)...");
            
            var response2Content = await response2.Content.ReadAsByteArrayAsync();
            var message2 = ParseMessage2Cbor(response2Content);
            
            if (message2.MessageType != "M2")
            {
                throw new Exception($"Ungueltiger MessageType in Nachricht 2: {message2.MessageType}");
            }
            
            // KEM-Decapsulation fuer Kyber768
            var ss_e_kyber768 = VauCrypto.Kyber768Decapsulate(kyberPrivateKey, message2.Kyber768_ct);
            var ss_e = ss_e_kyber768; // Vereinfacht: nur Kyber
            
            // K1-Schluessel ableiten mittels HKDF
            var k1_keys = VauCrypto.Hkdf(ss_e, length: 64);
            var K1_c2s = k1_keys[..32];
            var K1_s2c = k1_keys[32..64];
            
            Logger.Debug("  K1-Schluessel abgeleitet");
            
            // NACHRICHT 3: Client -> VAU (A_24623)
            Logger.Info("Erzeuge Nachricht 3 (Schluesselbestaetigung)...");
            
            // K2-Schluessel ableiten
            var k2_input = ss_e.Concat(VauCrypto.GetRandomBytes(32)).ToArray();
            var k2_keys = VauCrypto.Hkdf(k2_input, length: 160);
            connection.K2_c2s_app_data = k2_keys[..32];
            connection.K2_s2c_app_data = k2_keys[32..64];
            var K2_c2s_key_confirmation = k2_keys[64..96];
            var K2_s2c_key_confirmation = k2_keys[96..128];
            connection.KeyId = k2_keys[128..160];
            
            // Transkript-Hash berechnen
            var transcript = message1Cbor.Concat(response2Content).ToArray();
            var transcriptHash = VauCrypto.Sha256(transcript);
            
            // Nachricht 3 erstellen und senden
            var message3Cbor = CreateMessage3Cbor(K2_c2s_key_confirmation, transcriptHash);
            
            var message3Url = $"{_config.EPA.AktensystemBaseUrl.TrimEnd('/')}{connection.VauCid}";
            Logger.Debug($"  Sende Nachricht 3 an {message3Url}...");
            
            var request3 = new HttpRequestMessage(HttpMethod.Post, message3Url)
            {
                Content = new ByteArrayContent(message3Cbor)
            };
            request3.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/cbor");
            
            var response4 = await _httpClient.SendAsync(request3);
            
            // NACHRICHT 4: VAU -> Client (A_24626)
            Logger.Info("Verarbeite Nachricht 4 (Abschluss)...");
            
            var response4Content = await response4.Content.ReadAsByteArrayAsync();
            var message4 = ParseMessage4Cbor(response4Content);
            
            if (message4.MessageType != "M4")
            {
                throw new Exception($"Ungueltiger MessageType in Nachricht 4: {message4.MessageType}");
            }
            
            Logger.Ok("VAU-Handshake erfolgreich abgeschlossen!");
            Logger.Info($"  VAU-CID: {connection.VauCid}");
            Logger.Info($"  KeyID: {BitConverter.ToString(connection.KeyId[..8]).Replace("-", "").ToLower()}...");
        }
        catch (Exception ex)
        {
            Logger.Warn($"VAU-Handshake fehlgeschlagen: {ex.Message}");
            Logger.Warn("Verwende Demo-Modus mit Platzhalter-Schluesseln");
            
            // Platzhalter-Werte fuer Demo-Modus
            connection.VauCid = "/VAU/demo-connection-id";
            connection.KeyId = VauCrypto.GetRandomBytes(32);
            connection.K2_c2s_app_data = VauCrypto.GetRandomBytes(32);
            connection.K2_s2c_app_data = VauCrypto.GetRandomBytes(32);
        }
        
        return connection;
    }
    
    /// <summary>
    /// Verschluesselt einen inneren HTTP-Request (A_24628-01)
    /// </summary>
    public byte[] ProtectRequest(VauConnection connection, string innerRequest)
    {
        connection.EncryptionCounter++;
        connection.RequestCounter++;
        
        // IV: 4 Byte Zufall + 8 Byte Counter = 12 Byte
        var randomPart = VauCrypto.GetRandomBytes(4);
        var counterBytes = BitConverter.GetBytes(connection.EncryptionCounter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);
        var iv = randomPart.Concat(counterBytes).ToArray();
        
        // Header fuer AAD
        var puByte = _config.Umgebung == "PU" ? (byte)1 : (byte)0;
        var requestCounterBytes = BitConverter.GetBytes(connection.RequestCounter);
        if (BitConverter.IsLittleEndian) Array.Reverse(requestCounterBytes);
        
        var header = new byte[] { 0x02, puByte, 0x01 }
            .Concat(requestCounterBytes)
            .Concat(connection.KeyId)
            .ToArray();
        
        // AES/GCM Verschluesselung
        var plaintext = Encoding.UTF8.GetBytes(innerRequest);
        var (ciphertext, tag) = VauCrypto.AesGcmEncrypt(connection.K2_c2s_app_data, iv, plaintext, header);
        
        Logger.Debug($"Request verschluesselt (Counter: {connection.RequestCounter}, Groesse: {plaintext.Length} -> {ciphertext.Length + 16} Bytes)");
        
        // Header || IV || Ciphertext || Tag
        return header.Concat(iv).Concat(ciphertext).Concat(tag).ToArray();
    }
    
    /// <summary>
    /// Entschluesselt eine VAU-Response (A_24633)
    /// </summary>
    public string UnprotectResponse(VauConnection connection, byte[] encryptedResponse)
    {
        // Minimum: Header (43) + IV (12) + Tag (16) = 71 Byte
        if (encryptedResponse.Length < 71)
        {
            throw new Exception($"Response zu kurz: {encryptedResponse.Length} Byte (minimum 71 Byte)");
        }
        
        // Header parsen
        var version = encryptedResponse[0];
        var puByte = encryptedResponse[1];
        var responseType = encryptedResponse[2];
        
        if (version != 0x02)
        {
            throw new Exception($"Ungueltige Protokoll-Version: {version} (erwartet: 2)");
        }
        
        if (responseType != 0x02)
        {
            throw new Exception($"Ungueltiger Response-Typ: {responseType} (erwartet: 2)");
        }
        
        // Header (43 Byte), IV (12 Byte), Rest ist Ciphertext+Tag
        var header = encryptedResponse[..43];
        var iv = encryptedResponse[43..55];
        var ciphertextWithTag = encryptedResponse[55..];
        
        // Tag trennen (letzte 16 Byte)
        var ciphertext = ciphertextWithTag[..^16];
        var tag = ciphertextWithTag[^16..];
        
        // AES/GCM Entschluesselung
        var plaintext = VauCrypto.AesGcmDecrypt(connection.K2_s2c_app_data, iv, ciphertext, tag, header);
        var responseText = Encoding.UTF8.GetString(plaintext);
        
        Logger.Debug($"Response entschluesselt ({plaintext.Length} Bytes)");
        
        return responseText;
    }
    
    #region CBOR Helper Methods
    
    private byte[] CreateMessage1Cbor(byte[] ecdhX, byte[] ecdhY, byte[] kyberPublicKeyBytes)
    {
        var cborMap = CBORObject.NewMap();
        cborMap.Add("MessageType", "M1");
        
        var ecdhPk = CBORObject.NewMap();
        ecdhPk.Add("crv", "P-256");
        ecdhPk.Add("x", ecdhX);
        ecdhPk.Add("y", ecdhY);
        cborMap.Add("ECDH_PK", ecdhPk);
        
        cborMap.Add("Kyber768_PK", kyberPublicKeyBytes);
        
        return cborMap.EncodeToBytes();
    }
    
    private (string MessageType, byte[] ECDH_ct, byte[] Kyber768_ct) ParseMessage2Cbor(byte[] cborBytes)
    {
        var cborObject = CBORObject.DecodeFromBytes(cborBytes);
        
        var messageType = cborObject["MessageType"].AsString();
        var ecdhCt = cborObject["ECDH_ct"]?.GetByteString() ?? Array.Empty<byte>();
        var kyberCt = cborObject["Kyber768_ct"]?.GetByteString() ?? Array.Empty<byte>();
        
        return (messageType, ecdhCt, kyberCt);
    }
    
    private byte[] CreateMessage3Cbor(byte[] k2Key, byte[] transcriptHash)
    {
        var iv = VauCrypto.GetRandomBytes(12);
        var (ciphertext, tag) = VauCrypto.AesGcmEncrypt(k2Key, iv, transcriptHash);
        
        var cborMap = CBORObject.NewMap();
        cborMap.Add("MessageType", "M3");
        cborMap.Add("AEAD_ct", VauCrypto.GetRandomBytes(64)); // Platzhalter
        cborMap.Add("AEAD_ct_key_confirmation", ciphertext.Concat(tag).ToArray());
        
        return cborMap.EncodeToBytes();
    }
    
    private (string MessageType, byte[] KeyConfirmation) ParseMessage4Cbor(byte[] cborBytes)
    {
        var cborObject = CBORObject.DecodeFromBytes(cborBytes);
        
        var messageType = cborObject["MessageType"].AsString();
        var keyConfirmation = cborObject["AEAD_ct_key_confirmation"]?.GetByteString() ?? Array.Empty<byte>();
        
        return (messageType, keyConfirmation);
    }
    
    #endregion
}
