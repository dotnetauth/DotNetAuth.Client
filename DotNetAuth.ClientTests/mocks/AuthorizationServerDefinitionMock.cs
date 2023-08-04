using DotNetAuth.Client;

namespace DotNetAuth.ClientTests.Mocks
{
    class AuthorizationServerDefinitionMock : AuthorizationServerDefinitionBase
    {
        private readonly Dictionary<string, string>? getAuthorizationRequestParametersResponse;
        private readonly Dictionary<string, string>? getAccessTokenRequestParametersResponse;
        private readonly AuthorizationResponse? parseAccessTokenResultResponse;

        public AuthorizationServerDefinitionMock(string? authorizationEndpointUri = null, string? tokenEndpointUri = null, Dictionary<string, string>? getAuthorizationRequestParametersResponse = null, Dictionary<string, string>? getAccessTokenRequestParametersResponse = null, AuthorizationResponse? parseAccessTokenResultResponse = null) 
            : base(
                  authorizationEndpointUri: authorizationEndpointUri ?? "https://example.com/auth",
                  tokenEndpointUri: tokenEndpointUri ?? "https://example.com/token")
        {
            this.getAuthorizationRequestParametersResponse = getAuthorizationRequestParametersResponse;
            this.getAccessTokenRequestParametersResponse = getAccessTokenRequestParametersResponse;
            this.parseAccessTokenResultResponse = parseAccessTokenResultResponse;
        }

        public override Dictionary<string, string> GetAuthorizationRequestParameters(OAuthCredentials oauthCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, IStateStore? stateStore)
        {
            return this.getAuthorizationRequestParametersResponse ?? base.GetAuthorizationRequestParameters(oauthCredentials, redirectUri, scope, authorizationSettings, stateStore);
        }

        public override Dictionary<string, string> GetAccessTokenRequestParameters(OAuthCredentials oauthCredentials, string? redirectUri, string code, string grantType = "authorization_code")
        {
            return this.getAccessTokenRequestParametersResponse ?? base.GetAccessTokenRequestParameters(oauthCredentials, redirectUri, code, grantType);
        }

        public override AuthorizationResponse ParseAccessTokenResult(string body)
        {
            return this.parseAccessTokenResultResponse ?? base.ParseAccessTokenResult(body);
        }
    }

}