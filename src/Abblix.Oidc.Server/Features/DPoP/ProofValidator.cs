// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Validates a DPoP proof JWT per RFC 9449 section 4.2 / section 4.3 / section 11.1.5 covering structure,
/// algorithm whitelist, embedded-JWK shape, signature, the request-binding claim triplet
/// (<c>htm</c>, <c>htu</c>, optional <c>ath</c>), <c>iat</c> window, <c>jti</c> presence,
/// and <c>jti</c> replay protection against a shared cache. DPoP-Nonce checks layer on
/// top of the returned <see cref="Proof"/> in a separate slice.
/// </summary>
/// <remarks>
/// JWS structure parse, <c>typ</c> pinning, alg-whitelist enforcement, and signature
/// verification all delegate to <see cref="IJsonWebTokenValidator"/>. The
/// <see cref="ValidationOptions.UseEmbeddedVerificationKey"/> flag opts the call into the
/// DPoP "embedded jwk" trust model where the validator extracts the signing key from the
/// proof's <c>jwk</c> JOSE header parameter natively. ProofValidator therefore owns only
/// DPoP-specific concerns: the structural <c>jwk-no-private-key</c> rule, request-binding
/// claims, and replay protection.
/// </remarks>
internal sealed class ProofValidator(
    IJsonWebTokenValidator jwtValidator,
    IReplayCache replayCache,
    IOptionsMonitor<OidcOptions> options,
    IRequestInfoProvider requestInfoProvider,
    TimeProvider timeProvider) : IProofValidator
{
    private static readonly IReadOnlySet<string> ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal)
    {
        JsonWebTokenTypes.DPoPProof,
    };

    /// <inheritdoc/>
    public async Task<Result<Proof, ProofError>> ValidateAsync(
        string proofJwt,
        string? accessToken = null,
        CancellationToken cancellationToken = default)
    {
        // RFC 9449 section 7.1: a request MUST carry at most one DPoP header. ASP.NET Core's
        // string FromHeader binder joins repeated header values with a comma. The DPoP
        // proof is JWS compact serialization (RFC 7515 section 3.1), whose alphabet is
        // base64url + '.' - no comma is permitted - so a comma in the proof string
        // is unambiguous evidence that the client sent the header twice. Reject before
        // the downstream JWS validator sees a string with 5 dot-separated parts (which
        // it would route to the JWE branch and surface a category error).
        if (proofJwt.Contains(','))
        {
            return new ProofError(
                ProofErrorReasons.MalformedJwt,
                "Multiple DPoP header values are not permitted (RFC 9449 section 7.1).");
        }

        var jwtResult = await jwtValidator.ValidateAsync(
            proofJwt,
            new ()
            {
                Options = ValidationOptions.RequireSignedTokens | ValidationOptions.UseEmbeddedVerificationKey,
                ExpectedTokenTypes = ExpectedTokenTypes,
                AllowedSigningAlgorithms = DPoPAlgorithms.Allowed,
            });

        if (jwtResult.TryGetFailure(out var validationError))
            return new ProofError(ProofErrorReasons.Of(validationError.Error), validationError.ErrorDescription);

        var jwt = jwtResult.GetSuccess();
        DateTimeOffset issuedAt = default;
        var jwtId = string.Empty;

        var httpMethod = requestInfoProvider.RequestMethod;
        var requestUri = new Uri(requestInfoProvider.RequestUri);

        var error = ValidateJwkShape(jwt.Header, out var jwk) ??
                    ValidateRequestBinding(jwt.Payload, httpMethod, requestUri, out issuedAt) ??
                    ProofBindingClaims.AccessToken(jwt.Payload, accessToken) ??
                    TryGetJti(jwt.Payload, out jwtId);

        if (error != null)
            return error;

        // The latest moment a same-iat replay could still pass the iat-window check is
        // iat + tolerance; the replay-cache only needs to remember jti up to that point.
        // TryAddAsync is single-call by contract - atomic-capable backends close the
        // read-then-write race natively; the default IDistributedCache fallback retains
        // the documented probabilistic guarantee accepted under RFC 9449 section 11.1.
        var fresh = await replayCache.TryReserveAsync(
            jwtId,
            issuedAt + options.CurrentValue.DPoP.IssuedAtTolerance,
            cancellationToken);

        if (!fresh)
        {
            return new ProofError(
                ProofErrorReasons.ReplayDetected,
                "DPoP proof jti has already been used within the acceptance window.");
        }

        return new Proof(jwt, jwk, jwk.ComputeJwkThumbprintBase64Url(), jwtId, issuedAt);
    }

    /// <summary>
    /// Enforces the RFC 9449 section 4.2 rule that the embedded <c>jwk</c> MUST NOT contain
    /// private-key material. The JWT validator already extracted the JWK and used its
    /// public part to verify the signature, so the key is guaranteed non-null on the
    /// success path; this post-check catches accidental private-key disclosure before
    /// the proof is accepted.
    /// </summary>
    private static ProofError? ValidateJwkShape(JsonWebTokenHeader header, out JsonWebKey jwk)
    {
        jwk = header.VerificationKey.NotNull(nameof(header.VerificationKey));
        if (jwk.HasPrivateKey)
        {
            return new ProofError(
                ProofErrorReasons.InvalidJwk,
                $"Header '{JwtClaimTypes.JsonWebKeyHeader}' must not contain private key material.");
        }

        return null;
    }

    /// <summary>
    /// Validates the request-binding claims per RFC 9449 section 4.3: <c>htm</c> matches the
    /// request method byte-exact, <c>htu</c> matches the request URI after RFC 3986 section 6.2
    /// canonicalisation, and <c>iat</c> falls within the configured tolerance window
    /// around the server's current time. Returns the parsed <c>iat</c> on success.
    /// </summary>
    private ProofError? ValidateRequestBinding(
        JsonWebTokenPayload payload,
        string httpMethod,
        Uri requestUri,
        out DateTimeOffset issuedAt)
    {
        issuedAt = default;

        var error = ProofBindingClaims.HttpMethod(payload, httpMethod) ??
                    ProofBindingClaims.HttpUri(payload, requestUri) ??
                    TryGetIat(payload, out issuedAt);

        if (error != null)
            return error;

        var now = timeProvider.GetUtcNow();
        var tolerance = options.CurrentValue.DPoP.IssuedAtTolerance;
        if (tolerance < (issuedAt - now).Duration())
        {
            return new ProofError(
                ProofErrorReasons.IssuedAtOutOfWindow,
                $"iat is outside the {tolerance.TotalSeconds:0}-second tolerance window.");
        }

        return null;
    }

    /// <summary>
    /// Extracts the <c>iat</c> claim as a <see cref="DateTimeOffset"/>, distinguishing
    /// missing-from-malformed because the two cases need different operator responses.
    /// </summary>
    private static ProofError? TryGetIat(JsonWebTokenPayload payload, out DateTimeOffset issuedAt)
    {
        issuedAt = default;

        // Read through the payload's own guarded reader rather than the accessor: the proof is
        // validated without lifetime handling, so nothing before this line has touched the claim,
        // and the accessor throws on a value it cannot read. A private list of the exceptions it
        // throws is what stood here before, and the list was missing the one a number outside the
        // representable range raises.
        if (!payload.TryReadTimestamp(JwtClaimTypes.IssuedAt, out var iatNullable, out var whyUnreadable))
        {
            return new ProofError(ProofErrorReasons.IssuedAtInvalid, whyUnreadable);
        }

        if (iatNullable is null)
            return new ProofError(ProofErrorReasons.IssuedAtMissing, "iat claim is required.");

        issuedAt = iatNullable.Value;
        return null;
    }

    /// <summary>
    /// RFC 9449 section 4.2 floor on jti entropy: at least 96 bits of pseudorandom data
    /// (or a UUIDv4) so in-window collisions stay negligible. The strictest length
    /// floor that admits every conforming encoding is the byte count of the raw
    /// payload itself; every wider encoding (base64url, hex, UUIDv4) lands above.
    /// </summary>
    private const int MinJwtIdLengthInBits = 96;

    /// <summary>
    /// Extracts the <c>jti</c> claim, requiring a non-empty string per RFC 7519 section 4.1.7
    /// and at least <see cref="MinJwtIdLengthInBits"/> bits of entropy. The downstream
    /// replay-cache uses the value as its key.
    /// </summary>
    private static ProofError? TryGetJti(JsonWebTokenPayload payload, out string jti)
    {
        jti = null!;

        var value = payload.JwtId;
        if (string.IsNullOrEmpty(value))
            return new ProofError(ProofErrorReasons.JwtIdMissing, $"'{JwtClaimTypes.JwtId}' claim is required.");

        if (value.Length < MinJwtIdLengthInBits >> 3)
        {
            return new ProofError(
                ProofErrorReasons.JwtIdMissing,
                $"'{JwtClaimTypes.JwtId}' must carry at least {MinJwtIdLengthInBits} bits of entropy.");
        }

        jti = value;
        return null;
    }
}
