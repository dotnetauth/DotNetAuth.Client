namespace DotNetAuth.Client.Providers;

public class FacebookAuthorizationServerDefinition : AuthorizationServerDefinitionBase
{
    public FacebookAuthorizationServerDefinition() : base(
        authorizationEndpointUri : "https://www.facebook.com/v13.0/dialog/oauth", 
        tokenEndpointUri: "https://graph.facebook.com/v13.0/oauth/access_token")
    {
    }

    public override Dictionary<string, string> GetAuthorizationRequestParameters(ClientCredentials clientCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, string? state)
    {
        var result = base.GetAuthorizationRequestParameters(clientCredentials, redirectUri, scope, null, state);
        result.Add("auth_type", "reauthenticate");
        authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        return result;
    }
}
