namespace DotNetAuth.Client.Providers;

/// <summary>
/// OAuth 2 provider for Github accounts.
/// </summary>
public class GithubAuthorizationServerDefinition : AuthorizationServerDefinitionBase
{
    private readonly GithubAuthorizationSettings authorizationSettings;

    /// <summary>
    /// Initializes a new instance of the <see cref="GithubOAuth2"/> class.
    /// </summary>
    /// <param name="offline">if set to <c>true</c> you can use the refresh token to get new access token when your access token expires.</param>
    public GithubAuthorizationServerDefinition(GithubAuthorizationSettings authorizationSettings)
        : base(
            authorizationEndpointUri: "https://github.com/login/oauth/authorize",
            tokenEndpointUri: "https://github.com/login/oauth/access_token")
    {
        this.authorizationSettings = authorizationSettings;
    }

    /// <summary>
    /// Returns a list of parameters to be included in authorization endpoint as query string. 
    /// </summary>
    /// <param name="clientCredentials">The client's credentials.</param>
    /// <param name="redirectUri">The redirect URI in which OAuth user wishes sites user to be returned to finally</param>
    /// <param name="scope">The scope of access or set of permissions OAuth user is demanding.</param>
    /// <param name="stateManager">An implementation of <see cref="IStateStore"/> for providing state value.</param>
    /// <returns>A list of parameters to be included in authorization endpoint.</returns>
    public override Dictionary<string, string> GetAuthorizationRequestParameters(ClientCredentials clientCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, IStateStore? stateManager)
    {
        var result = base.GetAuthorizationRequestParameters(clientCredentials, redirectUri, scope, null, stateManager);
        this.authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        return result;
    }
}

public class GithubAuthorizationSettings : AuthorizationSettings
{
    private readonly bool? offline;
    private readonly bool? forceApprovalPrompt;

    public GithubAuthorizationSettings(bool? offline = null, bool? forceApprovalPrompt = null)
    {
        this.offline = offline;
        this.forceApprovalPrompt = forceApprovalPrompt;
    }

    public override void ModifyAuthorizationRequestParameters(Dictionary<string, string> authorizationRequestParameters)
    {
        base.ModifyAuthorizationRequestParameters(authorizationRequestParameters);

        var offlineValue = authorizationRequestParameters.GetValueOrDefault("access_type");
        if (offline != null)
            offlineValue = offline == true ? "offline" : "online";
        if (offlineValue != null)
            authorizationRequestParameters["access_type"] = offlineValue;


        var forceApprovalPromptValue = authorizationRequestParameters.GetValueOrDefault("prompt");
        if (forceApprovalPrompt != null)
            forceApprovalPromptValue = forceApprovalPrompt == true ? "consent" : null;
        if (forceApprovalPromptValue != null)
            authorizationRequestParameters["prompt"] = forceApprovalPromptValue;

    }
}
