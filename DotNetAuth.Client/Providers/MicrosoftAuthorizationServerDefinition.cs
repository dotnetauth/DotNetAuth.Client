namespace DotNetAuth.Client.Providers;

public class MicrosoftAuthorizationServerDefinition : AuthorizationServerDefinitionBase
{
    private readonly MicrosoftAuthorizationSettings authorizationSettings;

    public MicrosoftAuthorizationServerDefinition(MicrosoftAuthorizationSettings authorizationSettings)
        : base(
            authorizationEndpointUri: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            tokenEndpointUri: "https://login.microsoftonline.com/common/oauth2/v2.0/token")
    {
        this.authorizationSettings = authorizationSettings;
    }

    public override Dictionary<string, string> GetAuthorizationRequestParameters(ClientCredentials clientCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, IStateStore? stateManager)
    {
        var result = base.GetAuthorizationRequestParameters(clientCredentials, redirectUri, scope, null, stateManager);
        this.authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        authorizationSettings?.ModifyAuthorizationRequestParameters(result);
        return result;
    }
}


public class MicrosoftAuthorizationSettings : AuthorizationSettings
{
    private readonly bool? offline;

    public MicrosoftAuthorizationSettings(bool? offline = null)
    {
        this.offline = offline;
    }

    public override void ModifyAuthorizationRequestParameters(Dictionary<string, string> authorizationRequestParameters)
    {
        base.ModifyAuthorizationRequestParameters(authorizationRequestParameters);

        var offlineValue = authorizationRequestParameters.GetValueOrDefault("access_type");
        if (offline != null)
            offlineValue = offline == true ? "offline" : "online";
        if (offlineValue != null)
            authorizationRequestParameters["access_type"] = offlineValue;
    }
}