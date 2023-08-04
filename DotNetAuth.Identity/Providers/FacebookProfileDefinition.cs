using System.Text.Json;
using System.Text.Json.Nodes;

namespace DotNetAuth.Identity.Providers;

public class FacebookProfileDefinition : ProfileDefinitionBase
{
    ProfileProperty[] supportedProperties;
    public FacebookProfileDefinition() : base("Facebook", "Facebook")
    {
        supportedProperties = new[] {
            new ProfileProperty(ProfilePropertyNames.UniqueID, null, "id", "id"),
            new ProfileProperty(ProfilePropertyNames.BirthDate, "user_birthday", "birthday", "birthday"),
            new ProfileProperty(ProfilePropertyNames.DisplayName, null, "name", null),
            new ProfileProperty(ProfilePropertyNames.Email, "email", "email", "email"),
            new ProfileProperty(ProfilePropertyNames.FirstName, null, "first_name", "first_name"),
            new ProfileProperty(ProfilePropertyNames.FullName, null, "name", "name"),
            new ProfileProperty(ProfilePropertyNames.Gender, null, "gender", "gender"),
            new ProfileProperty(ProfilePropertyNames.LastName, null, "last_name", "last_name"),
            new ProfileProperty(ProfilePropertyNames.Locale, null, "locale", null),
            new ProfileProperty(ProfilePropertyNames.Location, "user_location", "location.name", "user_location"),
            new ProfileProperty(ProfilePropertyNames.PictureLink, null, "picture", "picture"),
            new ProfileProperty(ProfilePropertyNames.ProfileLink, null, "link", "link"),
            new ProfileProperty(ProfilePropertyNames.Timezone, null, "timezone", "timezone"),
            new ProfileProperty(ProfilePropertyNames.Username, null, "username", "username"),
            new ProfileProperty(ProfilePropertyNames.Website, "user_website", "website", "user_website"),
        };
    }

    public override ProfileProperty[] GetSupportedProperties()
    {
        return supportedProperties;
    }
    public override string GetRequiredScope(ProfileProperty[] requiredProperties)
    {
        var requiredScope = "email,user_location,user_birthday,user_website";
        if (requiredProperties != null)
            requiredScope = supportedProperties.GetScope(requiredProperties);
        return requiredScope;
    }

    public override async Task<Profile> GetProfile(string accessToken, ProfileProperty[] requiredProperties)
    {
        var fields = "id,name,first_name,last_name,link,username,gender,timezone,birthday,email,user_location,picture,user_website";
        if (requiredProperties != null)
            fields = string.Join(",", supportedProperties.Find(requiredProperties).Select(p=>p.EndpointSettings));

        var profileContent = await HttpClient.GetStringAsync($"https://www.googleapis.com/oauth2/v2/userinfo?");

        var jsonNode = JsonNode.Parse(profileContent) ?? throw new Exception("Unable to parse profile.");
        var idNode = jsonNode["id"] ?? throw new Exception("'id' value is missing");

        var result = new Profile
        {
            UniqueID = idNode.GetValue<string>(),
            DisplayName = jsonNode["name"]?.GetValue<string>(),
            FullName = jsonNode["name"]?.GetValue<string>(),
            Email = jsonNode["email"]?.GetValue<string>(),
            FirstName = jsonNode["first_name"]?.GetValue<string>(),
            LastName = jsonNode["last_name"]?.GetValue<string>(),
            ProfileLink = jsonNode["link"]?.GetValue<string>(),
            PictureLink = jsonNode["picture"]?.GetValue<string>(),
            Username = jsonNode["username"]?.GetValue<string>(),
            Gender = jsonNode["gender"]?.GetValue<string>(),
            Timezone = jsonNode["timezone"]?.GetValue<string>(),
            BirthDate = jsonNode["birthday"]?.GetValue<string>(),
            Location = jsonNode["location"]?["name"]?.GetValue<string>(),
            Website = jsonNode["website"]?.GetValue<string>(),
            Locale = jsonNode["locale"]?.GetValue<string>()
        };
        return result;
    }
}