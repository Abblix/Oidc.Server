namespace Abblix.Jwt;

/// <summary>
/// Provides access to the collections of JWE algorithms supported by the JWT infrastructure.
/// Tracks key-management and content-encryption algorithms as the corresponding encryptors are
/// registered in the dependency injection container.
/// </summary>
/// <remarks>
/// The provider maintains two lists — key-management algorithms (the JWE <c>alg</c>, e.g.
/// "RSA-OAEP-256") and content-encryption algorithms (the JWE <c>enc</c>, e.g. "A256GCM") — populated
/// during service registration via <see cref="AddKeyManagement"/> and <see cref="AddContentEncryption"/>,
/// and exposed via <see cref="KeyManagementAlgorithms"/> and <see cref="ContentEncryptionAlgorithms"/>
/// for discovery.
/// </remarks>
internal class EncryptionAlgorithmsProvider
{
    private readonly List<string> _keyManagementAlgorithms = [];
    private readonly List<string> _contentEncryptionAlgorithms = [];

    /// <summary>
    /// Gets the supported JWE key-management algorithms (the <c>alg</c> values, e.g. "RSA-OAEP-256").
    /// </summary>
    public IEnumerable<string> KeyManagementAlgorithms => _keyManagementAlgorithms;

    /// <summary>
    /// Gets the supported JWE content-encryption algorithms (the <c>enc</c> values, e.g. "A256GCM").
    /// </summary>
    public IEnumerable<string> ContentEncryptionAlgorithms => _contentEncryptionAlgorithms;

    /// <summary>
    /// Adds a key-management algorithm to the collection of supported algorithms.
    /// </summary>
    public void AddKeyManagement(string algorithm) => _keyManagementAlgorithms.Add(algorithm);

    /// <summary>
    /// Adds a content-encryption algorithm to the collection of supported algorithms.
    /// </summary>
    public void AddContentEncryption(string algorithm) => _contentEncryptionAlgorithms.Add(algorithm);
}
