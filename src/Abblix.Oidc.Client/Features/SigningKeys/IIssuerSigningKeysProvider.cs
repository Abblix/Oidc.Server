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

namespace Abblix.Oidc.Client.Features.SigningKeys;

/// <summary>
/// Supplies the keys that verify signatures made by the OpenID Provider.
/// </summary>
public interface IIssuerSigningKeysProvider
{
    /// <summary>
    /// Returns the provider's signature-verification keys, re-reading the key set when the token names a key
    /// that is not held.
    /// </summary>
    /// <param name="keyId">
    /// The <c>kid</c> the token to be verified names, or <c>null</c> when it names none.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// The keys to try. A named key that the provider publishes is returned alone; otherwise every held key
    /// is returned, so a token without a <c>kid</c> can still be verified by trying each.
    /// </returns>
    /// <remarks>
    /// Rotation is handled here rather than by each caller: a provider replaces its keys on its own schedule,
    /// and a token signed with a key the client has not seen yet is a normal event, not a rejection.
    /// </remarks>
    Task<IReadOnlyCollection<JsonWebKey>> GetSigningKeysAsync(
        string? keyId, CancellationToken cancellationToken = default);
}
