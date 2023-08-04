using System.Text.Json.Nodes;

namespace DotNetAuth.Identity.Providers;

public class GoogleProfileDefinition : ProfileDefinitionBase
{
    ProfileProperty[] supportedProperties;
    private const string UserProfileScope = "https://www.googleapis.com/auth/userinfo.profile";
    private const string EmailScope = "https://www.googleapis.com/auth/userinfo.email";
    public GoogleProfileDefinition() : base("Google", "Google")
    {
        supportedProperties = new[] {
            new ProfileProperty(ProfilePropertyNames.UniqueID, UserProfileScope, "id", null),
            new ProfileProperty(ProfilePropertyNames.DisplayName, UserProfileScope, "name", null),
            new ProfileProperty(ProfilePropertyNames.FirstName, UserProfileScope, "given_name", null),
            new ProfileProperty(ProfilePropertyNames.LastName, UserProfileScope, "family_name", null),
            new ProfileProperty(ProfilePropertyNames.ProfileLink, UserProfileScope, "link", null),
            new ProfileProperty(ProfilePropertyNames.FullName, UserProfileScope, "name", null),
            new ProfileProperty(ProfilePropertyNames.PictureLink, UserProfileScope, "picture", null),
            new ProfileProperty(ProfilePropertyNames.Gender, UserProfileScope, "gender", null),
            new ProfileProperty(ProfilePropertyNames.BirthDate, UserProfileScope, "birthday", null),
            new ProfileProperty(ProfilePropertyNames.Timezone, UserProfileScope, "timezone", null),
            new ProfileProperty(ProfilePropertyNames.Email, EmailScope, "email", null),
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
        var profileContent = await HttpClient.GetStringAsync($"https://www.googleapis.com/oauth2/v2/userinfo?access_token={accessToken}");

        var jsonNode = JsonNode.Parse(profileContent) ?? throw new Exception("Unable to parse profile.");
        var idNode = jsonNode["id"] ?? throw new Exception("'id' value is missing");

        var result = new Profile
        {
            UniqueID = idNode.GetValue<string>(),
            DisplayName = jsonNode["name"]?.GetValue<string>(),
            FirstName = jsonNode["given_name"]?.GetValue<string>(),
            LastName = jsonNode["family_name"]?.GetValue<string>(),
            ProfileLink = jsonNode["link"]?.GetValue<string>(),
            FullName = jsonNode["name"]?.GetValue<string>(),
            PictureLink = jsonNode["picture"]?.GetValue<string>(),
            Gender = jsonNode["gender"]?.GetValue<string>(),
            BirthDate = jsonNode["birthday"]?.GetValue<string>(),
            Timezone = jsonNode["timezone"]?.GetValue<string>(),
            Email = jsonNode["email"]?.GetValue<string>()
        };
        return result;
    }
}
