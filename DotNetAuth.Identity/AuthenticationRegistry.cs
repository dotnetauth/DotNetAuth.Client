using DotNetAuth.Client;

namespace DotNetAuth.Identity;

public class AuthenticationRegistry
{
    private Dictionary<string, OAuthCredentials> credentialsRegistry = new Dictionary<string, OAuthCredentials>();
    private Dictionary<string, ProfileDefinitionBase> profileRegistry = new Dictionary<string, ProfileDefinitionBase>();
    private Dictionary<string, AuthorizationServerDefinitionBase> providerRegistry = new Dictionary<string, AuthorizationServerDefinitionBase>();

    public void Add(string name, string clientId, string clientSecret, AuthorizationServerDefinitionBase providerDefinition, ProfileDefinitionBase profileDefinition)
    {
        var credentials = new OAuthCredentials(clientId, clientSecret);
        credentialsRegistry[name] = credentials;
        profileRegistry[name] = profileDefinition;
        providerRegistry[name] = providerDefinition;
    }

    public OAuthCredentials GetCredentialsFor(string name)
    {
        if (credentialsRegistry.ContainsKey(name))
        {
            return credentialsRegistry[name];
        }
        else
        {
            throw new Exception("No credentials found for the given name.");
        }
    }

    public ProfileDefinitionBase GetProfileDefinitionFor(string name)
    {
        if (profileRegistry.ContainsKey(name))
        {
            return profileRegistry[name];
        }
        else
        {
            throw new Exception("No profile definition found for the given name.");
        }
    }

    public AuthorizationServerDefinitionBase GetProviderDefinition(string name)
    {
        if (providerRegistry.ContainsKey(name))
        {
            return providerRegistry[name];
        }
        else
        {
            throw new Exception("No provider definition found for the given name.");
        }
    }
}


