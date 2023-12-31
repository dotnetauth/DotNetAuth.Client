using System.Web;

namespace DotNetAuth.Client;

/// <summary>
/// Handles the OAuth authentication process, including generating the authorization URL and processing the user's response.
/// </summary>
public class OAuth2Authenticator
{
    private readonly ICodeVerifierStore? codeVerifierStore;
    private readonly Func<HttpClient> httpClientFactory;

    /// <param name="stateStore">An instance of <see cref="IStateStore"/> for managing the state parameter.</param>
    /// <param name="codeVerifierStore">An instance of <see cref="ICodeVerifierStore"/> for managing the code verifier.</param>
    public OAuth2Authenticator(ICodeVerifierStore? codeVerifierStore, Func<HttpClient> httpClientFactory)
    {
        this.codeVerifierStore = codeVerifierStore;
        this.httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Generates the authorization URL to which the user should be redirected for the initial step of the OAuth authentication process.
    /// This URL leads to the authorization endpoint of the OAuth service provider, where the user can grant or deny access to your application.
    /// </summary>
    /// <param name="authorizationServerDefinition">An instance of a class representing an OAuth service provider. Predefined implementations can be found in the <see cref="DotNetAuth.OAuth2.Providers"/> namespace.</param>
    /// <param name="clientCredentials">Your application's credentials, obtained by registering your application with the service provider.</param>
    /// <param name="afterAuthenticationRedirectUri">The URI to which the service provider will redirect the user after they have made a decision about granting access to your application. This has to be matching the client registration.</param>
    /// <param name="accessScope">A string representing the scope of access rights your application is requesting. The format of this string depends on the service provider.</param>
    /// <returns>The authorization URL to which the user should be redirected.</returns>
    public Uri GenerateAuthorizeUri(AuthorizationServerDefinitionBase authorizationServerDefinition, ClientCredentials clientCredentials, string afterAuthenticationRedirectUri, string accessScope, string? state, AuthorizationSettings? authorizationSettings)
    {
        if (authorizationServerDefinition == null)
            throw new ArgumentNullException(nameof(authorizationServerDefinition));

        if (clientCredentials == null)
            throw new ArgumentNullException(nameof(clientCredentials));

        var authParams = authorizationServerDefinition.GetAuthorizationRequestParameters(clientCredentials, afterAuthenticationRedirectUri, accessScope, authorizationSettings, state);

        if (codeVerifierStore != null)
        {
            var codeVerifier = OAuthHandlerHelpers.GenerateCodeVerifier();
            var codeChallenge = OAuthHandlerHelpers.GenerateCodeChallenge(codeVerifier);
            codeVerifierStore.StoreCodeVerifier(codeVerifier);

            authParams.Add("code_challenge", codeChallenge);
            authParams.Add("code_challenge_method", "S256");
        }

        var endpointUri = new Uri(authorizationServerDefinition.AuthorizationEndpointUri, UriKind.RelativeOrAbsolute);

        // todo : this is wrong, because this doesn't comply with URL encoding rules, specifically the space character
        // perhaps write my own encoder
        var query = OAuthHandlerHelpers.EncodeForQueryString(authParams);

        var uriBuilder = new UriBuilder(endpointUri)
        {
            Query = query
        };

        return uriBuilder.Uri;
    }

    /// <summary>
    /// Processes the response from the service provider when the user is redirected back to your application after deciding whether to grant access.
    /// This method checks if the user has granted access and, if so, retrieves the access token.
    /// </summary>
    /// <param name="authorizationServerDefinition">An instance of a class representing the OAuth service provider.</param>
    /// <param name="clientCredentials">Your application's credentials.</param>
    /// <param name="receivedCallbackUrl">The full URL to which the user was redirected after OAuth provider's decision.</param>
    /// <param name="registeredRedirectUrl">The URL that was registered with the authorization server, used for verification.</param>
    /// <returns>A <see cref="AuthorizationResponse"/> object containing the access token and additional parameters, or error details if an error occurred.</returns>
    public async Task<AuthorizationResponse> HandleCallback(AuthorizationServerDefinitionBase authorizationServerDefinition, ClientCredentials clientCredentials, Uri receivedCallbackUrl, string registeredRedirectUrl, Func<string?, bool>? checkState)
    {
        var queryParameters = HttpUtility.ParseQueryString(receivedCallbackUrl.Query) ?? throw new Exception("Invalid response");

        // Check if the state parameter in the response matches the original state
        string? responseState = queryParameters.Get("state");
        var stateIsValid = checkState == null || checkState(responseState);
        if (!stateIsValid)
            throw new Exception("Invalid state or state not recognized.");

        #region Handle Error response
        var error = queryParameters.Get("error");
        if (!string.IsNullOrEmpty(error))
        {
            var errorDescription = queryParameters.Get("error_description");
            var errorUri = queryParameters.Get("error_uri");
            var parametersDictionary = new Dictionary<string, object>();
            foreach (var key in queryParameters.AllKeys)
            {
                parametersDictionary.Add(key!, queryParameters[key]!);
            }
            return new AuthorizationErrorResponse(parametersDictionary, error, errorDescription, errorUri);
        }
        #endregion

        var authCode = queryParameters.Get("code");
        if (string.IsNullOrEmpty(authCode))
            throw new Exception("code is missing in response");

        var tokenParams = authorizationServerDefinition.GetAccessTokenRequestParameters(clientCredentials, registeredRedirectUrl, authCode);

        if (codeVerifierStore != null)
        {
            var codeVerifier = codeVerifierStore.GetCodeVerifier();
            tokenParams.Add("code_verifier", codeVerifier);
        }

        var httpClient = httpClientFactory();
        var content = new FormUrlEncodedContent(tokenParams);
        var response = await httpClient.PostAsync(authorizationServerDefinition.TokenEndpointUri, content);
        var responseBody = await response.Content.ReadAsStringAsync();
        var output = authorizationServerDefinition.ParseAccessTokenResult(responseBody);
        return output;
    }
}
