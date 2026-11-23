// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The key the client secrets a tenant issues on dynamic registration are encrypted with, so the client configuration
/// endpoint can return a client its secret when it reads its registration (RFC 7592 section 3 and Appendix A.1). The
/// secret is verified against its hash as before; the encrypted value serves only that read.
/// </summary>
/// <remarks>
/// The secret is sealed the way pairwise subject identifiers are, by a deterministic authenticated encryption keyed by
/// <see cref="Key"/>, and bound to the tenant and the client, so a value moved to another client opens nowhere. A
/// server serving dynamic client registration refuses a tenant without these settings. A client registered before the
/// tenant had a key holds only the hash of its secret, so a read of its registration answers without the secret.
/// Replacing the key is allowed, and then every secret encrypted under the former one no longer opens: those clients
/// still authenticate with their secrets, and a read of their registration answers without the secret, with a warning
/// in the log.
/// </remarks>
public record ClientSecretEncryptionSettings
{
    /// <summary>
    /// A base64-encoded key of at least 32 bytes (256 bits) before encoding, kept secret. Use a key of its own rather
    /// than the pairwise salt.
    /// </summary>
    /// <remarks>
    /// Judged when the tenant declaring it enters the server, by the check of the tenant list, rather than on
    /// assignment, for the reason given on <see cref="PairwiseIdentifiers.PairwiseSubjectSettings.Salt"/>.
    /// </remarks>
    public required string Key { get; init; }

    /// <summary>
    /// The name of the hash the HKDF key derivation of the encryption uses: SHA256, SHA384 or SHA512, SHA256 when the
    /// setting is absent, while a setting with no value is refused. Changing it is changing the key.
    /// </summary>
    public string HashAlgorithm { get; init; } = nameof(HashAlgorithmName.SHA256);

    /// <summary>
    /// Why a tenant declaring <paramref name="settings"/> cannot be served, each reason, or none when it can: a server
    /// serving dynamic client registration needs the settings, since a client reading its registration is given its
    /// secret back, and settings declared must key the encryption.
    /// </summary>
    /// <param name="settings">The settings the tenant declares, or null when it declares none.</param>
    /// <param name="registrationServed">Whether the server serves dynamic client registration.</param>
    internal static IEnumerable<string> RefusalsOf(ClientSecretEncryptionSettings? settings, bool registrationServed)
    {
        if (settings is not null)
            return Refusals(settings);

        if (registrationServed)
            return [Missing];

        return [];
    }

    private const string Missing =
        $"{nameof(MultiTenancy.TenantDefinition.ClientSecretEncryption)} is required while the server serves dynamic " +
        "client registration, so that a client reading its registration is given its secret back (RFC 7592 section " +
        $"3): set {nameof(MultiTenancy.TenantDefinition.ClientSecretEncryption)}.{nameof(Key)} to a base64-encoded " +
        "random key of at least 32 bytes, kept secret.";

    /// <summary>Why <paramref name="settings"/> cannot key the encryption, each reason, or none when they can.</summary>
    /// <param name="settings">The settings a deployment configured.</param>
    internal static IEnumerable<string> Refusals(ClientSecretEncryptionSettings settings)
    {
        if (DeterministicSealKey.KeyRefusal(settings.Key, KeySetting, Seal) is { } key)
            yield return key;

        if (DeterministicSealKey.HashAlgorithmRefusal(settings.HashAlgorithm, HashSetting, Seal) is { } hash)
            yield return hash;
    }

    private const string Seal = "client secret encryption";
    private const string KeySetting = $"client secret encryption {nameof(Key)}";
    private const string HashSetting = $"client secret encryption {nameof(HashAlgorithm)}";
}
