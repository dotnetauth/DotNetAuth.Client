﻿using DotNetAuth.Client;

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

        public override Dictionary<string, string> GetAuthorizationRequestParameters(ClientCredentials clientCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, string? state)
        {
            return this.getAuthorizationRequestParametersResponse ?? base.GetAuthorizationRequestParameters(clientCredentials, redirectUri, scope, authorizationSettings, state);
        }

        public override Dictionary<string, string> GetAccessTokenRequestParameters(ClientCredentials clientCredentials, string? redirectUri, string code, string grantType = "authorization_code")
        {
            return this.getAccessTokenRequestParametersResponse ?? base.GetAccessTokenRequestParameters(clientCredentials, redirectUri, code, grantType);
        }

        public override AuthorizationResponse ParseAccessTokenResult(string body)
        {
            return this.parseAccessTokenResultResponse ?? base.ParseAccessTokenResult(body);
        }
    }

}