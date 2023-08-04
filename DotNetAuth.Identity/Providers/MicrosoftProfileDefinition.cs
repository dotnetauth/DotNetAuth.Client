using System.Text.Json;
using System.Text.Json.Nodes;

namespace DotNetAuth.Identity.Providers;

public class MicrosoftProfileDefinition : ProfileDefinitionBase
{
    ProfileProperty[] supportedProperties;
    private const string UserProfileScope = "https://graph.microsoft.com/User.Read";
    
    public MicrosoftProfileDefinition() : base("Microsoft", "Microsoft")
    {
        supportedProperties = new[] {
            new ProfileProperty(ProfilePropertyNames.UniqueID, UserProfileScope, "id", null),
            new ProfileProperty(ProfilePropertyNames.DisplayName, UserProfileScope, "displayName", null),
            new ProfileProperty(ProfilePropertyNames.Email, UserProfileScope, "mail", null)
        };
    }

    public override ProfileProperty[] GetSupportedProperties()
    {
        return supportedProperties;
    }

    public override string GetRequiredScope(ProfileProperty[] requiredProperties)
    {
        return supportedProperties.GetScope(requiredProperties, " ");
    }

    public override async Task<Profile> GetProfile(string accessToken, ProfileProperty[] requiredProperties)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/me");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Add("accept", "application/json");
        var profileResponse = await HttpClient.SendAsync(request);
        var profileContent = await profileResponse.Content.ReadAsStringAsync();

        var jsonNode = JsonNode.Parse(profileContent) ?? throw new Exception("Unable to parse profile.");
        var idNode = jsonNode["id"] ?? throw new Exception("'id' value is missing");

        var result = new Profile
        {
            UniqueID = idNode.GetValue<string>(),
            DisplayName = jsonNode["displayName"]?.GetValue<string>(),
            Email = jsonNode["mail"]?.GetValue<string>()
        };

        return result;
    }
}
