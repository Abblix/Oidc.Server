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

namespace Abblix.Oidc.Client.Features.TokenValidation;

/// <summary>
/// Establishes that a token was signed by the provider this client talks to and addressed to this client.
/// </summary>
/// <remarks>
/// The part every token from the provider needs and no token may skip: the signature against the issuer's
/// published keys, the algorithm against what this client accepts, the issuer against the one it is talking
/// to, the audience against its own identifier, and the expiry against the clock.
/// It is one component because the specifications say so in as many words. OpenID Connect Back-Channel
/// Logout 1.0 section 2.6 step 2 requires a Logout Token signature to be validated "in the same way that an
/// ID Token signature is validated", step 3 the same of the algorithm, and step 4 the same of "the iss, aud,
/// iat, and exp Claims". A second implementation of "the same way" is a second thing to keep in step, and
/// the copy nobody is looking at is where a weaker rule survives.
/// </remarks>
public interface IProviderTokenVerifier
{
    /// <summary>
    /// Verifies <paramref name="token"/> and returns it parsed.
    /// </summary>
    /// <param name="token">The encoded token as it arrived.</param>
    /// <param name="cancellationToken">Cancels the key-set and metadata reads this may need.</param>
    /// <returns>The verified token, whose claims are now the issuer's statements rather than the sender's.</returns>
    /// <remarks>
    /// Nothing may be read out of the token before this returns. RFC 8725 section 3.3 requires every
    /// cryptographic operation to be validated, and claims read ahead of that are attacker-controlled
    /// strings, however convenient the payload looks in a debugger.
    /// </remarks>
    /// <exception cref="ProviderTokenValidationException">The token was not accepted.</exception>
    Task<JsonWebToken> VerifyAsync(string token, CancellationToken cancellationToken = default);
}
