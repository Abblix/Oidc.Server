// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.IdentityTokens;

/// <summary>
/// Decides whether an ID Token may be believed, per the thirteen steps of OpenID Connect Core 1.0
/// section 3.1.3.7 and the flow-specific additions in sections 3.2.2.11 and 3.3.2.12.
/// </summary>
public interface IIdentityTokenValidator
{
    /// <summary>
    /// Validates <paramref name="identityToken"/> against <paramref name="context"/> and returns it
    /// parsed, or throws <see cref="IdentityTokenValidationException"/>.
    /// </summary>
    /// <param name="identityToken">The encoded ID Token as it arrived.</param>
    /// <param name="context">What this client sent and what arrived beside the token.</param>
    /// <param name="cancellationToken">Cancels the key-set and metadata reads this may need.</param>
    /// <returns>The validated token, whose claims may now be used to establish a session.</returns>
    /// <remarks>
    /// Nothing may be read out of an ID Token before this returns. RFC 8725 section 3.3 requires every
    /// cryptographic operation to be validated, and claims read ahead of that are attacker-controlled
    /// strings - the token is an untrusted blob until the signature over it says otherwise, however
    /// convenient its payload looks in a debugger.
    /// </remarks>
    Task<JsonWebToken> ValidateAsync(
        string identityToken,
        IdentityTokenValidationContext context,
        CancellationToken cancellationToken = default);
}
