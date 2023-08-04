namespace DotNetAuth.Identity;

public abstract class ProfileDefinitionBase
{
    protected static HttpClient HttpClient = new HttpClient();
    public ProfileDefinitionBase(string name, string fullName)
    {
        Name = name;
        Fullname = fullName;
    }
    public string Name { get; set; }
    public string Fullname { get; set; }
    public abstract ProfileProperty[] GetSupportedProperties();
    public abstract Task<Profile> GetProfile(string accessToken, ProfileProperty[] requiredProperties);
    public abstract string GetRequiredScope( ProfileProperty[] requiredProperties);
}
