// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// <param name="audienceKeys">Answers which key, if any, the named audience published.</param>
    /// <returns>The policy, pointed at the audience's key where one is published.</returns>
    /// <remarks>
    /// An audience that publishes no key leaves the policy untouched, which is how it says a signed JWS is
    /// what it expects. What makes a set of resources publish one key or none is
    /// <see cref="IAudienceKeyResolver"/>'s question.
    /// </remarks>
    public static async Task<ServiceJwtEncryption> WithAudienceKeyAsync(
        this ServiceJwtEncryption encryption,
        AuthorizationContext context,
        IAudienceKeyResolver audienceKeys)
    {
        if (context.Resources is not { Length: > 0 } resources)
            return encryption;

        return await audienceKeys.FindEncryptionKeyAsync(resources) is { } audienceKey
            ? encryption with { Key = audienceKey }
            : encryption;
    }
}
