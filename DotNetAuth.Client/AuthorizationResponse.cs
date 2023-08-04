namespace DotNetAuth.Client;

/// <summary>
/// Abstract base class for the authorization response.
/// </summary>
public abstract class AuthorizationResponse
{
    /// <summary>
    /// Gets all the parameters received in the authorization response.
    /// </summary>
    public Dictionary<string, object?> AllParameters { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationResponse"/> class.
    /// </summary>
    /// <param name="allParameters">All parameters received in the authorization response.</param>
    protected AuthorizationResponse(Dictionary<string, object?> allParameters)
    {
        AllParameters = allParameters;
    }
}

/// <summary>
/// Represents a successful authorization response.
/// </summary>
public class AuthorizationSuccessResponse : AuthorizationResponse
{
    /// <summary>
    /// Gets the access token.
    /// </summary>
    public string AccessToken { get; }

    /// <summary>
    /// Gets the type of the access token.
    /// </summary>
    public string? TokenType { get; }

    /// <summary>
    /// Gets the time in seconds in which the access token expires.
    /// </summary>
    public int? ExpiresIn { get; }

    /// <summary>
    /// Gets the refresh token, if provided.
    /// </summary>
    public string? RefreshToken { get; }

    /// <summary>
    /// Gets the scope of the access token, if provided.
    /// </summary>
    public string? Scope { get; }
    /// <summary>
    /// Gets the time when the access token was issued.
    /// </summary>
    public DateTime IssueTime { get; }

    /// <summary>
    /// Gets the state value that was passed to the authorization endpoint.
    /// </summary>
    public string? State { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationSuccessResponse"/> class.
    /// </summary>
    /// <param name="allParameters">All parameters received in the authorization response.</param>
    /// <param name="accessToken">The access token.</param>
    /// <param name="tokenType">The type of the access token.</param>
    /// <param name="expiresIn">The time in seconds in which the access token expires.</param>
    /// <param name="refreshToken">The refresh token, if provided.</param>
    /// <param name="scope">The scope of the access token, if provided.</param>
    /// <param name="issueTime">The time when the access token was issued.</param>
    public AuthorizationSuccessResponse(Dictionary<string, object?> allParameters, string accessToken, string? tokenType, int? expiresIn, string? refreshToken, string? scope, DateTime issueTime)
        : base(allParameters)
    {
        AccessToken = accessToken;
        TokenType = tokenType;
        ExpiresIn = expiresIn;
        RefreshToken = refreshToken;
        Scope = scope;
        IssueTime = issueTime;
    }
}

/// <summary>
/// Represents an error in the authorization response.
/// </summary>
public class AuthorizationErrorResponse : AuthorizationResponse
{

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationErrorResponse"/> class.
    /// </summary>
    /// <param name="allParameters">All parameters received in the authorization response.</param>
    /// <param name="error">The error code.</param>
    /// <param name="reason">The reason for the error.</param>
    /// <param name="description">The description of the error.</param>
    public AuthorizationErrorResponse(Dictionary<string, object> allParameters, string error, string? description, string? uri)
        : base(allParameters!)
    {
        Error = error;
        Description = description;
        Uri = uri;
    }

    /// <summary>
    /// Gets a value indicating whether the request was denied.
    /// </summary>
    public bool Denied => Error == "access_denied";

    /// <summary>
    /// Gets the error code provided by the service provider.
    /// </summary>
    public string Error { get; }

    /// <summary>
    /// Gets the description of the error.
    /// </summary>
    public string? Description { get; }
    public string? Uri { get; }
}
