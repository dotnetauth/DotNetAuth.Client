using System.Security.Cryptography;
using System.Text;

internal static class OAuthHandlerHelpers
{
    public static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=') // Remove any trailing '='s
            .Replace('+', '-') // 62nd char of encoding
            .Replace('/', '_'); // 63rd char of encoding
    }

    public static string EncodeForQueryString(IEnumerable<KeyValuePair<string, string>> nameValuePairs)
    {
        var result = new StringBuilder();
        bool first = true;

        foreach (var pair in nameValuePairs)
        {
            if (!first)
            {
                result.Append('&');
            }
            else
            {
                first = false;
            }

            result.Append(Uri.EscapeDataString(pair.Key));
            result.Append('=');
            result.Append(Uri.EscapeDataString(pair.Value));
        }

        return result.ToString();
    }

    public static string GenerateCodeChallenge(string codeVerifier)
    {
        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncode(bytes);
    }

    public static string GenerateCodeVerifier()
    {
        const string UnreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        int length = new Random().Next(43, 129); // Random length between 43 and 128
        var codeVerifier = new StringBuilder(length);

        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            byte[] randomBytes = new byte[length];
            rng.GetBytes(randomBytes);

            for (int i = 0; i < length; i++)
            {
                int charIndex = randomBytes[i] % UnreservedChars.Length;
                codeVerifier.Append(UnreservedChars[charIndex]);
            }
        }

        return codeVerifier.ToString();
    }
}