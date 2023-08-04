namespace DotNetAuth.Client;

/// <summary>
///  Interface for managing code verifier during OAuth 2 authentication process.
/// </summary>
public interface ICodeVerifierStore
{
    void StoreCodeVerifier(string codeVerifier);
    string GetCodeVerifier();
}
