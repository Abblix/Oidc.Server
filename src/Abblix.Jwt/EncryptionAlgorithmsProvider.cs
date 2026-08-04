using Abblix.Jwt.Encryption;

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Provides access to the collections of JWE algorithms supported by the JWT infrastructure.
/// Projects both sets - key-management algorithms (the JWE <c>alg</c>, e.g. "RSA-OAEP-256") and
/// content-encryption algorithms (the JWE <c>enc</c>, e.g. "A256GCM") - from the live keyed
/// <see cref="IKeyManagementAlgorithm{TJsonWebKey}"/> and <see cref="IContentEncryptionAlgorithm"/> registrations, so
/// discovery always reflects exactly the encryptors the host currently has registered - including
/// algorithms the host added or replaced - with no registration-time bookkeeping to keep in sync.
/// </summary>
/// <remarks>
/// The enumerated key types mirror the dispatch switch in <see cref="JsonWebTokenEncryptor"/>: an
/// encryptor registered for any other <see cref="JsonWebKey"/> subtype is unreachable at run time,
/// so it is deliberately not advertised. The enumeration order (RSA, EC, octet) preserves the order
/// the built-in algorithms have always appeared in published discovery documents.
/// </remarks>
internal sealed class EncryptionAlgorithmsProvider(IServiceProvider serviceProvider)
{
    /// <summary>
    /// Gets the supported JWE key-management algorithms (the <c>alg</c> values, e.g. "RSA-OAEP-256").
    /// </summary>
    public IEnumerable<string> KeyManagementAlgorithms =>
        KeyManagementAlgorithmsFor<RsaJsonWebKey>()
            .Concat(KeyManagementAlgorithmsFor<EllipticCurveJsonWebKey>())
            .Concat(KeyManagementAlgorithmsFor<OctetJsonWebKey>())
            .Distinct();

    /// <summary>
    /// Gets the supported JWE content-encryption algorithms (the <c>enc</c> values, e.g. "A256GCM").
    /// </summary>
    public IEnumerable<string> ContentEncryptionAlgorithms
        => serviceProvider
            .GetKeyedServices<IContentEncryptionAlgorithm>(KeyedService.AnyKey)
            .Select(encryptor => encryptor.Algorithm)
            .Distinct();

    private IEnumerable<string> KeyManagementAlgorithmsFor<TJsonWebKey>() where TJsonWebKey : JsonWebKey
        => serviceProvider
            .GetKeyedServices<IKeyManagementAlgorithm<TJsonWebKey>>(KeyedService.AnyKey)
            .Select(encryptor => encryptor.Algorithm);
}
