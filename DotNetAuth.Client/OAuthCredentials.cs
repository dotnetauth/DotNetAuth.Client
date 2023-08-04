namespace DotNetAuth.Client;

/// <summary>
/// Represents the application's identification keys for OAuth.
/// </summary>
/// <param name="ClientId"> The unique ID of the application, also known as 'client_id' in OAuth. </param>
/// <param name="ClientSecret"> The secret ID of the application, used to validate requests. </param>
/// <remarks>
/// </remarks>
public record OAuthCredentials(string ClientId, string ClientSecret);
