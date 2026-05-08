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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Validates a DPoP proof JWT per RFC 9449 §4.2 / §4.3 / §11.1.5 covering structure,
/// algorithm whitelist, embedded-JWK shape, signature, the request-binding claim triplet
/// (<c>htm</c>, <c>htu</c>, optional <c>ath</c>), <c>iat</c> window, <c>jti</c> presence,
/// and <c>jti</c> replay protection against a shared cache. DPoP-Nonce checks layer on
/// top of the returned <see cref="Proof"/> in a separate slice.
/// </summary>
/// <remarks>
/// JWS structure parse, <c>typ</c> pinning, alg-whitelist enforcement, and signature
/// verification all delegate to <see cref="IJsonWebTokenValidator"/>. The
/// <see cref="ValidationOptions.AllowMissingIssuer"/> flag opts the call into the DPoP
/// "embedded jwk" trust model where the validator extracts the signing key from the
/// proof's <c>jwk</c> JOSE header parameter natively. ProofValidator therefore owns only
/// DPoP-specific concerns: the structural <c>jwk-no-private-key</c> rule, request-binding
/// claims, and replay protection.
/// </remarks>
internal sealed class ProofValidator(
    IJsonWebTokenValidator jwtValidator,
    IJwtReplayCache replayCache,
    IOptionsMonitor<OidcOptions> options,
    TimeProvider timeProvider) : IProofValidator
{
    private static readonly IReadOnlySet<string> AllowedAlgorithms = new HashSet<string>(StringComparer.Ordinal)
    {
        SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
        SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512,
        SigningAlgorithms.ES256, SigningAlgorithms.ES384, SigningAlgorithms.ES512,
    };

    private static readonly IReadOnlySet<string> ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal)
    {
        JwtTypes.DPoPProof,
    };

    /// <inheritdoc/>
    public async Task<Result<Proof, ProofError>> ValidateAsync(
        string proofJwt,
        string httpMethod,
        Uri requestUri,
        string? accessToken = null,
        CancellationToken cancellationToken = default)
    {
        var jwtResult = await jwtValidator.ValidateAsync(proofJwt, new ValidationParameters
        {
            Options = ValidationOptions.RequireSignedTokens | ValidationOptions.UseEmbeddedVerificationKey,
            ExpectedTokenTypes = ExpectedTokenTypes,
            AllowedSigningAlgorithms = AllowedAlgorithms,
        });
        if (!jwtResult.TryGetSuccess(out var jwt))
            return MapValidationError(jwtResult.GetFailure());

        if (ValidateJwkShape(jwt.Header, out var jwk) is { } jwkError)
            return jwkError;
        if (ValidateRequestBinding(jwt.Payload.Json, httpMethod, requestUri, out var iat) is { } bindingError)
            return bindingError;
        if (ValidateAccessTokenBinding(jwt.Payload.Json, accessToken) is { } athError)
            return athError;
        if (TryGetJti(jwt.Payload.Json, out var jti) is { } jtiError)
            return jtiError;

        if (await replayCache.IsReplayedAsync(jti))
            return new ProofError(ProofErrorReasons.ReplayDetected,
                "DPoP proof jti has already been used within the acceptance window.");

        // The latest moment a same-iat replay could still pass the iat-window check is
        // iat + tolerance; the replay-cache only needs to remember jti up to that point.
        await replayCache.MarkAsUsedAsync(jti, iat + options.CurrentValue.DPoP.IssuedAtTolerance);

        return new Proof(jwk, jwk.ComputeJwkThumbprintBase64Url(), jti, iat);
    }

    /// <summary>
    /// Maps a typed <see cref="JwtValidationError"/> from the JWT validator onto the
    /// DPoP-specific reason taxonomy. The validator already covered JWS structure, typ
    /// pinning, alg-whitelist, header shape and signature verification; each
    /// <see cref="JwtError"/> category maps to the matching
    /// <see cref="ProofErrorReasons"/> token for log filters and metric labels.
    /// </summary>
    private static ProofError MapValidationError(JwtValidationError error)
    {
        var reason = error.Error switch
        {
            JwtError.MalformedToken => ProofErrorReasons.MalformedJwt,
            JwtError.InvalidAlgorithm => ProofErrorReasons.InvalidAlg,
            JwtError.InvalidTokenType => ProofErrorReasons.InvalidTyp,
            JwtError.InvalidHeader => ProofErrorReasons.InvalidJwk,
            JwtError.InvalidSignature => ProofErrorReasons.SignatureInvalid,
            _ => ProofErrorReasons.SignatureInvalid,
        };
        return new ProofError(reason, error.ErrorDescription);
    }

    /// <summary>
    /// Enforces the RFC 9449 §4.2 rule that the embedded <c>jwk</c> MUST NOT contain
    /// private-key material. The JWT validator already extracted the JWK and used its
    /// public part to verify the signature, so the key is guaranteed non-null on the
    /// success path; this post-check catches accidental private-key disclosure before
    /// the proof is accepted.
    /// </summary>
    private static ProofError? ValidateJwkShape(JsonWebTokenHeader header, out JsonWebKey jwk)
    {
        jwk = header.VerificationKey.NotNull(nameof(header.VerificationKey));
        return jwk.HasPrivateKey
            ? new ProofError(ProofErrorReasons.InvalidJwk, "Header 'jwk' must not contain private key material.")
            : null;
    }

    /// <summary>
    /// Validates the request-binding claims per RFC 9449 §4.3: <c>htm</c> matches the
    /// request method byte-exact, <c>htu</c> matches the request URI after RFC 3986 §6.2
    /// canonicalisation, and <c>iat</c> falls within the configured tolerance window
    /// around the server's current time. Returns the parsed <c>iat</c> on success.
    /// </summary>
    private ProofError? ValidateRequestBinding(JsonObject payloadObj, string httpMethod, Uri requestUri, out DateTimeOffset iat)
    {
        iat = default;

        if (ValidateHttpMethod(payloadObj, httpMethod) is { } htmError)
            return htmError;
        if (ValidateHttpUri(payloadObj, requestUri) is { } htuError)
            return htuError;
        if (TryGetIat(payloadObj, out var iatValue) is { } iatError)
            return iatError;

        var now = timeProvider.GetUtcNow();
        var tolerance = options.CurrentValue.DPoP.IssuedAtTolerance;
        if (tolerance < (iatValue - now).Duration())
        {
            return new ProofError(
                ProofErrorReasons.IatOutOfWindow,
                $"iat is outside the {tolerance.TotalSeconds:0}-second tolerance window.");
        }

        iat = iatValue;
        return null;
    }

    /// <summary>
    /// Compares the proof's <c>htm</c> claim against the current request method
    /// byte-exact (RFC 9449 §4.3).
    /// </summary>
    private static ProofError? ValidateHttpMethod(JsonObject payloadObj, string httpMethod)
    {
        var htm = ReadStringClaim(payloadObj, JwtClaimTypes.DPoPHttpMethod);
        return htm == httpMethod
            ? null
            : new ProofError(ProofErrorReasons.HtmMismatch,
                $"htm '{htm ?? "<missing>"}' does not match request method '{httpMethod}'.");
    }

    /// <summary>
    /// Compares the proof's <c>htu</c> claim against the current request URI after
    /// RFC 3986 §6.2 canonicalisation.
    /// </summary>
    private static ProofError? ValidateHttpUri(JsonObject payloadObj, Uri requestUri)
    {
        var htu = ReadStringClaim(payloadObj, JwtClaimTypes.DPoPHttpUri);
        if (htu is null)
            return new ProofError(ProofErrorReasons.HtuMissing, "htu claim is required.");
        if (!Uri.TryCreate(htu, UriKind.Absolute, out var htuUri))
            return new ProofError(ProofErrorReasons.HtuInvalid, "htu is not a valid absolute URI.");
        return htuUri.Normalize() == requestUri.Normalize()
            ? null
            : new ProofError(ProofErrorReasons.HtuMismatch, "htu does not match the request URI after canonicalisation.");
    }

    /// <summary>
    /// Extracts the <c>iat</c> claim as a <see cref="DateTimeOffset"/>, distinguishing
    /// missing-from-malformed because the two cases need different operator responses.
    /// </summary>
    private static ProofError? TryGetIat(JsonObject payloadObj, out DateTimeOffset iat)
    {
        iat = default;
        DateTimeOffset? iatNullable;
        try { iatNullable = payloadObj.GetUnixTimeSeconds(JwtClaimTypes.IssuedAt); }
        catch
        {
            return new ProofError(ProofErrorReasons.IatInvalid, "iat claim is not a valid Unix-time numeric.");
        }
        if (iatNullable is null)
            return new ProofError(ProofErrorReasons.IatMissing, "iat claim is required.");
        iat = iatNullable.Value;
        return null;
    }

    /// <summary>
    /// When the proof accompanies an access token, verifies the <c>ath</c> claim equals
    /// <c>Base64Url(SHA-256(access_token))</c> per RFC 9449 §4.2.
    /// </summary>
    private static ProofError? ValidateAccessTokenBinding(JsonObject payloadObj, string? accessToken)
    {
        if (accessToken is null)
            return null;

        var ath = ReadStringClaim(payloadObj, JwtClaimTypes.DPoPAccessTokenHash);
        if (ath is null)
            return new ProofError(ProofErrorReasons.AthMissing,
                "ath claim is required when an access token is presented.");

        var expectedAth = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        return ath == expectedAth
            ? null
            : new ProofError(ProofErrorReasons.AthMismatch, "ath does not match the access-token hash.");
    }

    /// <summary>
    /// Extracts the <c>jti</c> claim, requiring a non-empty string per RFC 7519 §4.1.7.
    /// The downstream replay-cache uses this value as its key.
    /// </summary>
    private static ProofError? TryGetJti(JsonObject payloadObj, out string jti)
    {
        jti = null!;
        var value = ReadStringClaim(payloadObj, JwtClaimTypes.JwtId);
        if (string.IsNullOrEmpty(value))
            return new ProofError(ProofErrorReasons.JtiMissing, "jti claim is required.");
        jti = value;
        return null;
    }

    /// <summary>
    /// Reads a string-typed claim by name, returning <c>null</c> when the claim is
    /// missing or not a JSON string.
    /// </summary>
    private static string? ReadStringClaim(JsonObject payloadObj, string name)
        => payloadObj[name]?.AsValue().TryGetValue<string>(out var value) == true ? value : null;
}
