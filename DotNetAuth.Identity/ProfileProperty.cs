namespace DotNetAuth.Identity;

public record ProfileProperty(string PropertyName, string? RequiredScope, string NativePropertyName, string? EndpointSettings)
{
    public string PropertyName { get; private set; } = PropertyName;
    public string? RequiredScope { get; private set; } = RequiredScope;
    public string? EndpointSettings { get; private set; } = EndpointSettings;
    public string NativePropertyName { get; private set; } = NativePropertyName;

    public static implicit operator string(ProfileProperty property) => property.PropertyName;

    public static implicit operator ProfileProperty(string propertyName) => new ProfileProperty(propertyName, null, propertyName, null);
}

public class ProfilePropertyNames
{
    public const string UniqueID = "UniqueID";
    public const string FirstName = "FirstName";
    public const string LastName = "LastName";
    public const string FullName = "FullName";
    public const string DisplayName = "DisplayName";
    public const string Username = "Username";
    public const string ProfileLink = "ProfileLink";
    public const string PictureLink = "PictureLink";
    public const string Gender = "Gender";
    public const string BirthDate = "BirthDate";
    public const string Timezone = "Timezone";
    public const string Email = "Email";
    public const string Location = "Location";
    public const string Website = "Website";
    public const string Locale = "Locale";
}
