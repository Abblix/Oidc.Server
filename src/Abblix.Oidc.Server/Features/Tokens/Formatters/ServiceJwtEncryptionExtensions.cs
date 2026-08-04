// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ResourceIndicators;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Completes a <see cref="ServiceJwtEncryption"/> policy from the request it is about to serve.
/// </summary>
public static class ServiceJwtEncryptionExtensions
{
    /// <summary>
    /// Points the policy at the key published by the resource this token was minted for, so the party named in
    /// <c>aud</c> can read it.
    /// </summary>
    /// <param name="encryption">The policy projected from the server's own settings.</param>
    /// <param name="context">The authorization context naming the token's audience.</param>
    /// <param name="resourceManager">Resolves a requested resource URI to its registered definition.</param>
    /// <param name="resourceKeysProvider">Supplies that resource's published encryption keys.</param>
    /// <returns>The policy, pointed at the audience's key where one is published.</returns>
    /// <remarks>
    /// A resource that publishes no key leaves the policy untouched, which is how it says a signed JWS is what
    /// it expects. Several audiences each publishing a key have no correct answer: compact JWE serialization
    /// carries one recipient, so encrypting to one of them would silently leave the token unreadable to the
    /// rest - refuse instead of choosing. Unknown resources never reach here, having been rejected as
    /// <c>invalid_target</c> during request validation (RFC 8707 Section 2).
    /// </remarks>
    public static async Task<ServiceJwtEncryption> WithAudienceKeyAsync(
        this ServiceJwtEncryption encryption,
        AuthorizationContext context,
        IResourceManager resourceManager,
        IResourceKeysProvider resourceKeysProvider)
    {
        if (context.Resources is not { Length: > 0 } resources)
            return encryption;

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

        return audienceKey is null ? encryption : encryption with { Key = audienceKey };
    }
}
