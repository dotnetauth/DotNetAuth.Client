using DotNetAuth.Client;

namespace DotNetAuth.Identity;

/// <summary>
/// Provides methods for managing user identity using OAuth.
/// </summary>
public class IdentityService
{
    private readonly OAuth2Authenticator oauthHandler;
    private readonly AuthenticationRegistry authenticationRegistry;

    /// <summary>
    /// Initializes a new instance of the <see cref="IdentityService"/> class.
    /// </summary>
    /// <param name="oauthHandler">An instance of <see cref="OAuthHandler"/> to handle OAuth operations.</param>
    /// <param name="authenticationRegistry">An instance of <see cref="AuthenticationRegistry"/> to manage authentication providers.</param>
    public IdentityService(OAuth2Authenticator oauthHandler, AuthenticationRegistry authenticationRegistry)
    {
        this.oauthHandler = oauthHandler;
        this.authenticationRegistry = authenticationRegistry;
    }

    /// <summary>
    /// Gets the authentication URI for a specific provider.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="rediredUri">The URI to redirect to after authentication.</param>
    /// <param name="requiredProperties">The required profile properties.</param>
    /// <returns>The authentication URI.</returns>
    public Uri GetAuthenticationUri(string provider, Uri rediredUri, ProfileProperty[] requiredProperties, string state, AuthorizationSettings authorizationSettings)
    {
        var credentials = authenticationRegistry.GetCredentialsFor(provider);
        var definition = authenticationRegistry.GetProfileDefinitionFor(provider);
        var handler = authenticationRegistry.GetProviderDefinition(provider);

        var scope = definition.GetRequiredScope(requiredProperties);

        return oauthHandler.GenerateAuthorizeUri(
            handler,
            credentials,
            rediredUri.AbsoluteUri,
            scope,
            state,
            authorizationSettings);
    }

    /// <summary>
    /// Gets the profile of a user from a specific provider.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="requestedUri">The requested URI.</param>
    /// <param name="redirectUri">The URI to redirect to after authentication.</param>
    /// <param name="requiredProperties">The required profile properties.</param>
    /// <returns>The user's profile.</returns>
    /// <exception cref="System.Exception">Thrown when login fails.</exception>
    public async Task<Profile> GetProfile(string provider, Uri requestedUri, string redirectUri, Func<string?, bool>? checkState, ProfileProperty[] requiredProperties)
    {
        var credentials = authenticationRegistry.GetCredentialsFor(provider);
        var definition = authenticationRegistry.GetProfileDefinitionFor(provider);
        var handler = authenticationRegistry.GetProviderDefinition(provider);

        var response = await oauthHandler.HandleCallback(
            handler,
            credentials,
            requestedUri,
            redirectUri,
            checkState);

        if (response != null)
        {
            if (response is AuthorizationSuccessResponse successResponse)
            {
                var access_token = successResponse.AccessToken;
                return await definition.GetProfile(access_token, requiredProperties); 
            }
            if (response is AuthorizationErrorResponse errorResponse)
            {
                throw new Exception(errorResponse.Description);
            }
        }

        throw new Exception("Login failed");
    }
}
