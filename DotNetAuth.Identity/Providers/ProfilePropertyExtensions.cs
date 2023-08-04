
namespace DotNetAuth.Identity.Providers;

public static class ProfilePropertyExtensions
{
    public static ProfileProperty? Find(this ProfileProperty[] supportedProperties, ProfileProperty requiredProperty)
    {
        return supportedProperties.Where(p => p.PropertyName == requiredProperty.PropertyName).SingleOrDefault();
    }
    public static ProfileProperty[] Find(this ProfileProperty[] supportedProperties, ProfileProperty[] requiredProperties)
    {
        return supportedProperties.Where(sp => requiredProperties.Any(rp => rp.PropertyName == sp.PropertyName)).ToArray();
    }
    public static string GetScope(this ProfileProperty[] supportedProperties, ProfileProperty[] requiredProperties, string separator = ",")
    {
        if (requiredProperties == null)
            return "";
        return string.Join(separator, supportedProperties.Find(requiredProperties).Select(p => p.RequiredScope).Distinct().ToArray());
    }
}
