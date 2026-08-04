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
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Validation;
using Abblix.Utils;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// The out-of-the-box verifier: signature verification through the Abblix JWT core, with keys
/// from the issuer resolver.
/// </summary>
/// <remarks>
/// The core is asked for exactly the signature - a signed token, verified against the issuer's
/// keys - and nothing more: issuer allowlisting, audience, freshness and typing are pipeline
/// steps, and letting the core re-check them would report their failures in the wrong vocabulary
/// from the wrong place. An issuer the resolver yields no keys for is reported as a key miss
/// rather than a bad signature, because a refetch may heal the former and never the latter.
/// </remarks>
/// <param name="validator">The JWT core's validator.</param>
/// <param name="keyResolver">The receiver's key trust.</param>
public sealed class DefaultSecurityEventTokenVerifier(
    IJsonWebTokenValidator validator,
    IIssuerKeyResolver keyResolver) : ISecurityEventTokenVerifier
{
    /// <inheritdoc />
    public async Task<Result<JsonWebToken, SecurityEventTokenValidationError>> VerifyAsync(
        string compactToken,
        string? keyId = null,
        CancellationToken cancellationToken = default)
    {
        // The core streams keys per issuer; buffering them first is what lets an empty set be
        // told apart from a signature that no key verified - the distinction the error codes
        // promise the receiver.
        var noKeysResolved = false;

        var parameters = new ValidationParameters
        {
            Options = ValidationOptions.RequireSignedTokens | ValidationOptions.ValidateIssuerSigningKey,
            ResolveIssuerSigningKeys = ResolveBuffered,
        };

        var result = await validator.ValidateAsync(compactToken, parameters);

        return result.Match<Result<JsonWebToken, SecurityEventTokenValidationError>>(
            token => token,
            jwtError => Translate(jwtError, noKeysResolved));

        async IAsyncEnumerable<JsonWebKey> ResolveBuffered(string issuer)
        {
            var keys = new List<JsonWebKey>();
            await foreach (var key in keyResolver.ResolveSigningKeysAsync(issuer, keyId, cancellationToken))
            {
                keys.Add(key);
            }

            noKeysResolved = keys.Count == 0;

            foreach (var key in keys)
            {
                yield return key;
            }
        }
    }

    private static SecurityEventTokenValidationError Translate(JwtValidationError error, bool noKeysResolved)
    {
        var code = error.Error switch
        {
            JwtError.MalformedToken => SecurityEventTokenErrorCode.MalformedToken,
            _ when noKeysResolved => SecurityEventTokenErrorCode.KeyNotFound,
            _ => SecurityEventTokenErrorCode.SignatureInvalid,
        };

        return new SecurityEventTokenValidationError(code, error.ErrorDescription);
    }
}
