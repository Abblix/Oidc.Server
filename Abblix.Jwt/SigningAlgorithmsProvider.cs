namespace Abblix.Jwt;

/// <summary>
/// Provides access to the collection of signing algorithms supported by the JWT infrastructure.
/// Tracks signing algorithms as IDataSigner services are registered in the dependency injection container.
/// </summary>
/// <remarks>
/// This provider maintains a list of algorithm identifiers (e.g., "RS256", "ES256", "HS256")
/// that are added during service registration. The list is populated by calling <see cref="Add"/>
/// for each registered signing algorithm and is exposed via <see cref="Algorithms"/> for discovery.
/// </remarks>
internal class SigningAlgorithmsProvider
{
    private readonly List<string> _algorithms = [];

    /// <summary>
    /// Gets the collection of signing algorithms supported for JWT creation and validation.
    /// Returns algorithm identifiers as they were registered (e.g., "RS256", "ES384", "HS512").
    /// </summary>
    public IEnumerable<string> Algorithms => _algorithms;

    /// <summary>
    /// Adds a signing algorithm to the collection of supported algorithms.
    /// Called during service registration for each IDataSigner being registered.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier (e.g., "RS256", "ES256", "HS256").</param>
    public void Add(string algorithm) => _algorithms.Add(algorithm);
}
