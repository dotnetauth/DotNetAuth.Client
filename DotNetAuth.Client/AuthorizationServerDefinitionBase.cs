using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DotNetAuth.Client;

/// <summary>
/// Provides basic methods to handle the authorization process using the OAuth protocol.
/// </summary>
public abstract class AuthorizationServerDefinitionBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationServerDefinitionBase"/> class.
    /// </summary>
    /// <param name="authorizationEndpointUri">The URI of the authorization endpoint.</param>
    /// <param name="tokenEndpointUri">The URI of the token endpoint.</param>
    protected AuthorizationServerDefinitionBase(string authorizationEndpointUri, string tokenEndpointUri)
    {
        AuthorizationEndpointUri = authorizationEndpointUri;
        TokenEndpointUri = tokenEndpointUri;
    }

    // for unit tests
    public AuthorizationServerDefinitionBase() : this("", "") { }


    /// <summary>
    /// Gets or sets the URI of the authorization endpoint in the resource server's domain. This is the first step in the authentication process where the user will be redirected. The user can grant or deny access to your app at this endpoint. If the user is not logged in to the resource server, they will be asked to log in. If they are logged in and have previously authorized your app, they will be immediately redirected back to your app.
    /// </summary>
    public virtual string AuthorizationEndpointUri { get; init; }

    /// <summary>
    /// Gets or sets the URI of the token endpoint in the resource server's domain. This endpoint is used to make a server-side request to exchange a code for an access token. The code is passed to your app by the resource server when redirecting users to your site as a query string parameter. This code is accessible to the user and anyone on the wire. Your app is the only one who can exchange it for an access token because you know the application credential used to generate the code, and this credential will be checked before producing an access token.
    /// </summary>
    public virtual string TokenEndpointUri { get; init; }

    /// <summary>
    /// Returns a list of parameters to be included in authorization endpoint as query string. 
    /// </summary>
    /// <remarks>
    /// When implementing a custom provider you need to override this method and fill the list of parameters according to the provider's documentation.
    /// However the default implementation provides a response for common OAuth parameters(e.g client_id,redirect_uri,scope,state,response_type)
    /// </remarks>
    /// <param name="oauthCredentials">The client's credentials.</param>
    /// <param name="redirectUri">The redirect URI in which OAuth client wishes sites user to be returned to finally</param>
    /// <param name="scope">The scope of access or set of permissions OAuth client is demanding.</param>
    /// <param name="stateStore">An implementation of <see cref="IStateStore"/> for providing state value.</param>
    /// <returns>A list of parameters to be included in authorization endpoint.</returns>
    public virtual Dictionary<string,string> GetAuthorizationRequestParameters(OAuthCredentials oauthCredentials, string? redirectUri, string? scope, AuthorizationSettings? authorizationSettings, IStateStore? stateStore)
    {
        var result = new Dictionary<string, string>{ 
            {"client_id", oauthCredentials.ClientId},
            {"response_type", "code"},
        };

        if( stateStore != null)
            result.Add("state", stateStore.GetState());
        if(scope != null)
            result.Add("scope", scope);
        if (redirectUri != null)
            result.Add("redirect_uri", redirectUri);

        authorizationSettings?.ModifyAuthorizationRequestParameters(result);

        return result;
    }

    /// <summary>
    /// Returns a list of parameters to be included in the token endpoint to exchange the authorization code for an access token.
    /// </summary>
    /// <param name="oauthCredentials">The user's application credentials.</param>
    /// <param name="redirectUri">The redirectUri URI where the OAuth user wishes the user to be returned to finally.</param>
    /// <param name="code">The authorization code received from the authorization endpoint.</param>
    /// <param name="grantType">The grant type for the access token request. Default is "authorization_code".</param>
    /// <returns>A list of parameters to be included in the token endpoint.</returns>
    public virtual Dictionary<string,string> GetAccessTokenRequestParameters(OAuthCredentials oauthCredentials, string? redirectUri, string code, string grantType = "authorization_code")
    {
        var result = new Dictionary<string, string> {
            {"code", code},
            {"client_id", oauthCredentials.ClientId},
            {"client_secret", oauthCredentials.ClientSecret},
            {"grant_type", grantType}
        };
        if (redirectUri != null)
            result.Add("redirect_uri", redirectUri);
        return result;
    }

    /// <summary>
    /// Parses the response body from the access token request and extracts the access token, expiration time, and refresh token.
    /// </summary>
    /// <param name="body">The response body of request for access token.</param>
    /// <returns>A <see cref="AuthorizationResponse"/> object containing access token and some additional parameters or error details.</returns>
    public virtual AuthorizationResponse ParseAccessTokenResult(string body)
    {
        var root = JsonNode.Parse(body) ?? throw new Exception("Invalid JSON response");
        var allParameters = root.Deserialize<Dictionary<string, object>>() ?? throw new Exception("Invalid JSON response");
        var errorNode = root["error"];
        if ( errorNode != null)
        {
            string error = errorNode.GetValue<string>();
            string? error_description = root["error_description"]?.GetValue<string>();
            string? error_uri = root["error_uri"]?.GetValue<string>();            

            return new AuthorizationErrorResponse(allParameters, error, error_description, error_uri);
        }

        var accessTokenNode = root["access_token"] ?? throw new Exception("Invalid JSON response, access_token is missing");
        string access_token = accessTokenNode.GetValue<string>();
        string? token_type = root["token_type"]?.GetValue<string>();
        int? expires_in = root["expires_in"]?.GetValue<int>();

        string? refresh_token = root["refresh_token"]?.GetValue<string>();
        string? scope = root["scope"]?.GetValue<string>();

        return new AuthorizationSuccessResponse(allParameters!, access_token, token_type, expires_in, refresh_token, scope, DateTime.UtcNow);
    }
}
