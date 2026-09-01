// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
/// <param name="allowedAlgorithms">What this deployment will accept a signature under. Stated rather
/// than inherited: without it the accepted set is whatever the validator happens to permit, which is a
/// policy nobody wrote and nobody can read off the configuration.</param>
public sealed class DefaultSecurityEventTokenVerifier(
    IJsonWebTokenValidator validator,
    IIssuerKeyResolver keyResolver,
    string[] allowedAlgorithms) : ISecurityEventTokenVerifier
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
            AllowedSigningAlgorithms = allowedAlgorithms.ToHashSet(StringComparer.Ordinal),
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

            // A token whose STRUCTURE the core refuses - a malformed 'crit' header, an unusable 'jwk' -
            // is a token that does not conform, not a key problem, so it goes to the code whose wire word
            // is invalid_request rather than the one whose word is invalid_key. Without this a correctly
            // signed SET with a bad 'crit' told the transmitter its keys were unacceptable.
            //
            // Safe HERE and only here, because of the parameters built above: the issuer, audience and
            // lifetime stages all return the token untouched when their option is not requested, and this
            // verifier requests none of them - the SET pipeline asks those questions itself, in its own
            // vocabulary. Adding one of those options to the parameters would put an expired or
            // wrong-audience token into this arm, where "cannot be parsed" is false of it.
            JwtError.InvalidHeader => SecurityEventTokenErrorCode.MalformedToken,

            _ when noKeysResolved => SecurityEventTokenErrorCode.KeyNotFound,

            // An algorithm this receiver does not accept lands here with everything else the core
            // refuses a signature over, and that is not a loss of meaning: RFC 8935 Section 2.4 renders
            // it as invalid_key, "unacceptable to the SET Recipient", which is what it is. Reading it
            // out of JwtError.InvalidAlgorithm instead would be wrong - that category also carries a
            // missing alg, an unregistered one and an unsigned token, and this seam cannot tell them
            // apart. The description says which happened, and the core writes it where the branch is
            // known.
            _ => SecurityEventTokenErrorCode.SignatureInvalid,
        };

        return new SecurityEventTokenValidationError(code, error.ErrorDescription);
    }
}
