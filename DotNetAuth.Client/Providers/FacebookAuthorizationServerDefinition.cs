namespace DotNetAuth.Client.Providers;

public class FacebookAuthorizationServerDefinition : AuthorizationServerDefinitionBase
{
    public FacebookAuthorizationServerDefinition() : base(
        authorizationEndpointUri : "https://www.facebook.com/v13.0/dialog/oauth", 
        tokenEndpointUri: "https://graph.facebook.com/v13.0/oauth/access_token")
    {
    }

    public override Dictionary<string, string> GetAuthorizationRequestParameters(OAuthCredentials oauthCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, IStateStore? stateManager)
    {
        var result = base.GetAuthorizationRequestParameters(oauthCredentials, redirectUri, scope, null, stateManager);
        result.Add("auth_type", "reauthenticate");
        authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        return result;
    }
}
