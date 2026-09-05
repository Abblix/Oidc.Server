// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

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
    /// The encryption key published by the audience named in <paramref name="resources"/>, or <c>null</c>
    /// when none of them publishes one.
    /// </summary>
    /// <param name="resources">The resources the token is minted for.</param>
    /// <remarks>
    /// A resource that publishes no key contributes nothing, which is how it says a signed JWS is what it
    /// expects. Several resources each publishing a key have no correct answer: compact JWE serialization
    /// carries one recipient, so encrypting to one of them would silently leave the token unreadable to the
    /// rest - refuse instead of choosing. Unknown resources never reach here, having been rejected as
    /// <c>invalid_target</c> during request validation (RFC 8707 Section 2).
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Several of the named resources each publish an encryption key.</exception>
    Task<JsonWebKey?> FindEncryptionKeyAsync(IReadOnlyCollection<Uri> resources);
}

/// <summary>
/// Answers from the resource registry, taking the first published key per resource.
/// </summary>
/// <param name="resourceManager">Resolves a requested resource URI to its registered definition.</param>
/// <param name="resourceKeysProvider">Supplies that resource's published encryption keys.</param>
public class AudienceKeyResolver(
    IResourceManager resourceManager,
    IResourceKeysProvider resourceKeysProvider) : IAudienceKeyResolver
{
    /// <inheritdoc />
    public async Task<JsonWebKey?> FindEncryptionKeyAsync(IReadOnlyCollection<Uri> resources)
    {
        JsonWebKey? audienceKey = null;
        Uri? keyOwner = null;

        foreach (var resource in resources)
        {
            if (!resourceManager.TryGet(resource, out var definition))
                continue;

            var key = await resourceKeysProvider.GetEncryptionKeys(definition).FirstOrDefaultAsync();
            if (key is null)
                continue;

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
