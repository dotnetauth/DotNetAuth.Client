using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;

namespace DotNetAuth.Identity.Providers;

public class GithubProfileDefinition : ProfileDefinitionBase
{
    ProfileProperty[] supportedProperties;
    private const string UserProfileScope = "read:user";
    private const string EmailScope = "user:email";

    public GithubProfileDefinition() : base("Github", "Github")
    {
        supportedProperties = new[] {
            new ProfileProperty(ProfilePropertyNames.UniqueID, UserProfileScope, "id", null),
            new ProfileProperty(ProfilePropertyNames.DisplayName, UserProfileScope, "login", null),
            new ProfileProperty(ProfilePropertyNames.FullName, UserProfileScope, "name", null),
            new ProfileProperty(ProfilePropertyNames.ProfileLink, UserProfileScope, "html_url", null),
            new ProfileProperty(ProfilePropertyNames.PictureLink, UserProfileScope, "avatar_url", null),
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
        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Add("user-agent", "DotNetAuth");
        request.Headers.Add("accept", "application/json");
        var profileResponse = await HttpClient.SendAsync(request);
        var profileContent = await profileResponse.Content.ReadAsStringAsync();

        var jsonNode = JsonNode.Parse(profileContent) ?? throw new Exception("Unable to parse profile.");
        var idNode = jsonNode["id"] ?? throw new Exception("'id' value is missing");

        var result = new Profile
        {
            UniqueID = idNode.GetValue<int>().ToString(),
            DisplayName = jsonNode["login"]?.GetValue<string>(),
            FullName = jsonNode["name"]?.GetValue<string>(),
            ProfileLink = jsonNode["html_url"]?.GetValue<string>(),
            PictureLink = jsonNode["avatar_url"]?.GetValue<string>(),
            Email = jsonNode["email"]?.GetValue<string>()
        };

        if (string.IsNullOrEmpty(result.Email))
        {
            // https://api.github.com/user/emails
            var emailRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/emails");
            emailRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            emailRequest.Headers.Add("user-agent", "DotNetAuth");
            emailRequest.Headers.Add("accept", "application/json");
            var emailResponse = await HttpClient.SendAsync(emailRequest);
            var emailContent = await emailResponse.Content.ReadAsStringAsync();

            var emailJsonNode = JsonNode.Parse(emailContent) ?? throw new Exception("Unable to parse email.");
            var emailNode = emailJsonNode.AsArray().FirstOrDefault(x => x?["primary"]?.GetValue<bool>() == true);
            if (emailNode != null)
            {
                result.Email = emailNode["email"]?.GetValue<string>();
            }

        }

        return result;
    }

}
