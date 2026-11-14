// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Finds the one encryption key a token's audience published, if any.
/// </summary>
/// <remarks>
/// Owns the question rather than leaving its two halves - resolving a resource to its definition and
/// reading that definition's keys - to every consumer that asks it. A token service needs the answer,
/// not the mechanics.
/// </remarks>
public interface IAudienceKeyResolver
{
    /// <summary>
    /// The encryption key published by the audience named in <paramref name="resources"/>, with the key management
    /// algorithm to encrypt to it under, or <c>null</c> when none of them publishes one.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="resources">The resources the token is minted for.</param>
    /// <param name="profile">The controls in force for the token, which the algorithm must satisfy.</param>
    /// <param name="defaultAlgorithm">The algorithm used for a key that declares none.</param>
    /// <remarks>
    /// A resource that publishes no key contributes nothing, which is how it says a signed JWS is what it
    /// expects. Several resources each publishing a key have no correct answer: compact JWE serialization
    /// carries one recipient, so encrypting to one of them would silently leave the token unreadable to the
    /// rest - refuse instead of choosing. Unknown resources never reach here, having been rejected as
    /// <c>invalid_target</c> during request validation (RFC 8707 Section 2).
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Several of the named resources each publish an encryption key.</exception>
    /// <exception cref="AudienceKeyRefusedException">A named resource publishes encryption keys, none of which this
    /// server can encrypt to under <paramref name="profile"/>.</exception>
    Task<AudienceEncryptionKey?> FindEncryptionKeyAsync(
        TenantDefinition tenant,
        IReadOnlyCollection<Uri> resources,
        SecurityProfileRequirements profile,
        string defaultAlgorithm);
}

/// <summary>
/// Answers from the resource registry, taking per resource the first published key a token can be encrypted to, with
/// its algorithm (<see cref="ProfiledJwtIssuer.EncryptionAlgorithmFor"/>).
/// </summary>
/// <param name="resourceManager">Resolves a requested resource URI to its registered definition.</param>
/// <param name="resourceKeysProvider">Supplies that resource's published encryption keys.</param>
/// <param name="issuer">Says which of them a token can be encrypted to, and under which algorithm.</param>
public class AudienceKeyResolver(
    IResourceManager resourceManager,
    IResourceKeysProvider resourceKeysProvider,
    ProfiledJwtIssuer issuer) : IAudienceKeyResolver
{
    /// <inheritdoc />
    public async Task<AudienceEncryptionKey?> FindEncryptionKeyAsync(
        TenantDefinition tenant,
        IReadOnlyCollection<Uri> resources,
        SecurityProfileRequirements profile,
        string defaultAlgorithm)
    {
        AudienceEncryptionKey? audienceKey = null;
        Uri? keyOwner = null;

        foreach (var resource in resources)
        {
            if (!resourceManager.TryGet(tenant, resource, out var definition))
                continue;

            var keys = await resourceKeysProvider.GetEncryptionKeys(definition).ToArrayAsync();
            if (keys.Length == 0)
                continue;

            // A set may also hold keys no token can be encrypted to (declaring a signing algorithm, one the host did
            // not register or the profile forbids, or of a type the default algorithm does not fit), and the next one
            // is taken; a resource holding only such keys still asks for encryption, so it is refused
            var key = keys
                    .Select(candidate => issuer.EncryptionAlgorithmFor(profile, candidate, defaultAlgorithm) is { } algorithm
                        ? new AudienceEncryptionKey(candidate, algorithm)
                        : null)
                    .FirstOrDefault(candidate => candidate is not null)
                ?? throw new AudienceKeyRefusedException(
                    [resource],
                    $"The resource '{resource}' publishes no encryption key this server can encrypt an access " +
                    "token to under the security profile in force");

            if (audienceKey is not null)
            {
                throw new InvalidOperationException(
                    $"The access token names several resources that each publish an encryption key " +
                    $"('{keyOwner}' and '{resource}'), and an encrypted JWT has a single recipient. " +
                    $"Request one such resource per token, or remove the key from all but one of them.");
            }

            audienceKey = key;
            keyOwner = resource;
        }

        return audienceKey;
    }
}
