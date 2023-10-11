namespace DotNetAuth.Client.Providers;

/// <summary>
/// OAuth 2 provider for Google accounts.
/// </summary>
public class GoogleAuthorizationServerDefinition : AuthorizationServerDefinitionBase
{
    private readonly GoogleAuthorizationSettings? authorizationSettings;

    /// <summary>
    /// Initializes a new instance of the <see cref="GoogleOAuth2"/> class.
    /// </summary>
    /// <param name="offline">if set to <c>true</c> you can use the refresh token to get new access token when your access token expires.</param>
    /// <param name="forceApprovalPrompt">if set to <c>true</c> even though user previously has permitted your application, the authentication page will be shown to him, so, for example, they can login using a different user.</param>
    public GoogleAuthorizationServerDefinition(GoogleAuthorizationSettings authorizationSettings)
        : base(
            authorizationEndpointUri: "https://accounts.google.com/o/oauth2/auth",
            tokenEndpointUri: "https://accounts.google.com/o/oauth2/token")
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
    public override Dictionary<string, string> GetAuthorizationRequestParameters(ClientCredentials clientCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, string? state)
    {
        var result = base.GetAuthorizationRequestParameters(clientCredentials, redirectUri, scope, null, state);
        this.authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        return result;
    }
}


public class GoogleAuthorizationSettings : AuthorizationSettings
{
    private readonly bool? offline;
    private readonly bool? forceApprovalPrompt;
    private readonly bool? includeGrantedScopes;
    private readonly string? loginHint;

    public GoogleAuthorizationSettings(bool? offline = null, bool? forceApprovalPrompt = null, bool? includeGrantedScopes = false, string? loginHint = null)
    {
        this.offline = offline ?? false;
        this.forceApprovalPrompt = forceApprovalPrompt ?? false;
        this.includeGrantedScopes = includeGrantedScopes ?? false;
        this.loginHint = loginHint;
    }

    public override void ModifyAuthorizationRequestParameters(Dictionary<string, string> authorizationRequestParameters)
    {
        base.ModifyAuthorizationRequestParameters(authorizationRequestParameters);

        var offlineValue = authorizationRequestParameters.GetValueOrDefault("offline");
        if (offline != null)
            offlineValue = offline == true ? "offline" : "online";
        if (offlineValue != null)
            authorizationRequestParameters["offline"] = offlineValue;


        var forceApprovalPromptValue = authorizationRequestParameters.GetValueOrDefault("approval_prompt");
        if (forceApprovalPrompt != null)
            forceApprovalPromptValue = forceApprovalPrompt == true ? "force" : "auto";
        if (forceApprovalPromptValue != null)
            authorizationRequestParameters["approval_prompt"] = forceApprovalPromptValue;


        var includeGrantedScopesValue = authorizationRequestParameters.GetValueOrDefault("include_granted_scopes");
        if (includeGrantedScopes != null)
            includeGrantedScopesValue = includeGrantedScopes == true ? "true" : "false";
        if (includeGrantedScopesValue != null)
            authorizationRequestParameters["include_granted_scopes"] = includeGrantedScopesValue;

        var login_hintValue = loginHint ?? authorizationRequestParameters.GetValueOrDefault("login_hint");
        if (login_hintValue != null)
            authorizationRequestParameters["login_hint"] = login_hintValue;
    }
}