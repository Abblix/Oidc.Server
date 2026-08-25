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

        // The token names a key the receiver's document does not hold. Said in the description and not in
        // the CODE, which drives the receiver's retry: the resolver already refetches on an unseen key
        // identifier, bounded by its own cooldown, so a second layer of retrying above it would buy
        // nothing and cost a request per forged token. What is missing is not a decision, it is the
        // sentence that tells an operator which way to look - a key document that has aged out reports as
        // a signature that does not verify, and that reads as a forged token to the first person who sees
        // it.
        var namedKeyMissing = false;

        var parameters = new ValidationParameters
        {
            Options = ValidationOptions.RequireSignedTokens | ValidationOptions.ValidateIssuerSigningKey,
            ResolveIssuerSigningKeys = ResolveBuffered,
        };

        var result = await validator.ValidateAsync(compactToken, parameters);

        return result.Match<Result<JsonWebToken, SecurityEventTokenValidationError>>(
            token => token,
            jwtError => Translate(jwtError, noKeysResolved, namedKeyMissing, keyId));

        async IAsyncEnumerable<JsonWebKey> ResolveBuffered(string issuer)
        {
            var keys = new List<JsonWebKey>();
            await foreach (var key in keyResolver.ResolveSigningKeysAsync(issuer, keyId, cancellationToken))
            {
                keys.Add(key);
            }

            noKeysResolved = keys.Count == 0;
            namedKeyMissing = keyId is not null && keys.TrueForAll(key => key.KeyId != keyId);

            foreach (var key in keys)
            {
                yield return key;
            }
        }
    }

    private static SecurityEventTokenValidationError Translate(
        JwtValidationError error,
        bool noKeysResolved,
        bool namedKeyMissing,
        string? keyId)
    {
        var code = error.Error switch
        {
            JwtError.MalformedToken => SecurityEventTokenErrorCode.MalformedToken,
            _ when noKeysResolved => SecurityEventTokenErrorCode.KeyNotFound,
            _ => SecurityEventTokenErrorCode.SignatureInvalid,
        };

        // Named, because the identifier is the whole diagnosis: it says the receiver is reading a
        // different key document from the one the issuer signs with, and it says which key would have
        // answered. Without it the operator has a failed signature and no reason to suspect wiring.
        var description = namedKeyMissing
            ? error.ErrorDescription
              + $" The token names key '{keyId}', which is not among the keys this receiver holds for that"
              + " issuer, so the key document it reads is not the one the issuer signs with."
            : error.ErrorDescription;

        return new SecurityEventTokenValidationError(code, description);
    }
}
