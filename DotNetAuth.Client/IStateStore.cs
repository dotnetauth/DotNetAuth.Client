namespace DotNetAuth.Client;

/// <summary>
/// Interface for managing state during OAuth 2 authentication process.
/// </summary>
public interface IStateStore
{
    /// <summary>
    /// Produces a unique value to be returned after user is redirected back to the application.
    /// </summary>
    /// <returns>A unique state value.</returns>
    string GetState();

    /// <summary>
    /// Validates the state value returned with the user's response.
    /// </summary>
    /// <param name="stateCode">The state value.</param>
    /// <returns>True if the stateCode is valid, otherwise false.</returns>
    bool CheckState(string? stateCode);
}
