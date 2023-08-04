namespace DotNetAuth.Client;

/// <summary>
/// Represents settings for modifying authorization requests.
/// </summary>
public class AuthorizationSettings
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationSettings"/> class.
    /// </summary>
    public AuthorizationSettings() { }

    /// <summary>
    /// Modifies the provided authorization request parameters based on specific criteria or requirements.
    /// </summary>
    public virtual void ModifyAuthorizationRequestParameters(Dictionary<string, string> authorizationRequestParameters)
    {

    }
}
