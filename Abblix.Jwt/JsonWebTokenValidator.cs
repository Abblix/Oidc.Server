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

using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

using System.Buffers.Text;

namespace Abblix.Jwt;

/// <summary>
/// Represents a validator for JSON Web Tokens (JWTs) which validates a JWT against specified validation parameters.
/// </summary>
/// <param name="timeProvider">Provides access to the current time for lifetime validation.</param>
/// <param name="encryptor">The JWE encryptor for decrypting encrypted tokens.</param>
/// <param name="signer">The JWS signer for validating signatures.</param>
/// <param name="signingAlgorithmsProvider">The provider for supported signing algorithms.</param>
/// <param name="serviceProvider">Resolves keyed <see cref="ICriticalHeaderHandler"/> registrations
/// when validating a JWS 'crit' header (RFC 7515 §4.1.11). Hosts register a handler keyed by each
/// understood JOSE header parameter name via
/// <see cref="ServiceCollectionExtensions.AddCriticalHeaderHandler{THandler}"/>.</param>
internal class JsonWebTokenValidator(
    TimeProvider timeProvider,
    IJsonWebTokenEncryptor encryptor,
    IJsonWebTokenSigner signer,
    SigningAlgorithmsProvider signingAlgorithmsProvider,
    IServiceProvider serviceProvider) : IJsonWebTokenValidator
{
    /// <summary>
    /// Header parameter names defined by RFC 7515 §4.1 (and 'crit' itself). Per RFC 7515 §4.1.11
    /// a producer MUST NOT list any of these in 'crit'; we reject as recipient-MAY because
    /// strict input parsing for security-critical formats is the right default.
    /// </summary>
    private static readonly IReadOnlySet<string> ReservedCriticalHeaderNames = new HashSet<string>(StringComparer.Ordinal)
    {
        JwtClaimTypes.Algorithm,
        JwtClaimTypes.KeyId,
        JwtClaimTypes.Type,
        JwtClaimTypes.ContentType,
        JwtClaimTypes.EncryptionAlgorithm,
        JwtClaimTypes.Critical,
        JwtClaimTypes.JwkSetUrl,
        JwtClaimTypes.JsonWebKeyHeader,
        JwtClaimTypes.X509Url,
        JwtClaimTypes.X509CertificateChain,
        JwtClaimTypes.X509Sha1Thumbprint,
        JwtClaimTypes.X509Sha256Thumbprint,
    };

    /// <summary>
    /// Provides a collection of signing algorithms supported by the validator.
    /// Dynamically determined from registered signers in the dependency injection container.
    /// </summary>
    public IEnumerable<string> SigningAlgorithmsSupported => signingAlgorithmsProvider.Algorithms;

    /// <summary>
    /// Asynchronously validates a JWT string against specified validation parameters.
    /// </summary>
    /// <param name="jwt">The JWT string to validate.</param>
    /// <param name="parameters">The parameters defining the validation rules and requirements.</param>
    /// <returns>A task representing the validation operation,
    /// with a result containing either a validated JsonWebToken or a JwtValidationError.</returns>
    public async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        string jwt,
        ValidationParameters parameters)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return new JwtValidationError(JwtError.MalformedToken, "JWT is null or empty");

        var jwtParts = jwt.Split('.');
        return jwtParts.Length switch
        {
            3 => await ValidateJwsAsync(jwtParts, parameters),
            5 => await DecryptJweAsync(jwtParts, parameters),
            _ => new JwtValidationError(
                JwtError.MalformedToken,
                $"Invalid JWT format: expected 3 or 5 dot-separated parts, got {jwtParts.Length}"),
        };
    }

    /// <summary>
    /// Validates a JWS token from string parts.
    /// Creates JsonWebToken only after successful validation.
    /// </summary>
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateJwsAsync(
        string[] jwtParts,
        ValidationParameters parameters)
    {
        return await ParseJws(jwtParts).BindAsync<JsonWebToken>(async token =>
        {
            var error =
                await ValidateSignatureAsync(token, jwtParts, parameters) ??
                ValidateCriticalHeaders(token.Header) ??
                ValidateTokenType(token.Header, parameters) ??
                await ValidateIssuerAsync(token.Payload.Issuer, parameters) ??
                await ValidateAudienceAsync(token.Payload.Audiences, parameters) ??
                ValidateLifetime(token.Payload, parameters);

            return error != null ? error : token;
        });
    }

    /// <summary>
    /// Parses JWS string parts into header, payload, and signature.
    /// </summary>
    private static Result<JsonWebToken, JwtValidationError> ParseJws(string[] jwtParts)
    {
        byte[] headerPart, payloadPart;
        try
        {
            headerPart = Base64Url.DecodeFromChars(jwtParts[0]);
            payloadPart = Base64Url.DecodeFromChars(jwtParts[1]);
        }
        catch
        {
            return new JwtValidationError(JwtError.MalformedToken, "Invalid JWT format: base64url decoding failed");
        }

        if (!TryParseJsonObject(headerPart, out var headerObject))
            return new JwtValidationError(JwtError.MalformedToken, "Invalid JWS header: must be a JSON object");

        if (!TryParseJsonObject(payloadPart, out var payloadObject))
            return new JwtValidationError(JwtError.MalformedToken, "Invalid JWS payload: must be a JSON object");

        var token = new JsonWebToken
        {
            Header = new (headerObject),
            Payload = new (payloadObject),
        };

        return token;
    }

    private static bool TryParseJsonObject(byte[] jwtPart, [NotNullWhen(true)] out JsonObject? jsonObject)
    {
        var json = Encoding.UTF8.GetString(jwtPart);
        try
        {
            jsonObject = JsonNode.Parse(json) as JsonObject;
        }
        catch (JsonException)
        {
            jsonObject = null;
        }
        return jsonObject is not null;
    }

    /// <summary>
    /// Validates the JWS signature according to validation parameters.
    /// </summary>
    private async Task<JwtValidationError?> ValidateSignatureAsync(
        JsonWebToken token,
        string[] jwtParts,
        ValidationParameters parameters)
    {
        // Per RFC 7515 Section 4.1.1, 'alg' parameter is REQUIRED
        var algorithm = token.Header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidAlgorithm, "Missing algorithm in JWT header");

        // Reject anything outside the registered RFC 7518 §3 alg taxonomy with the matching
        // taxonomy-level error. Without this gate, an unknown alg (e.g. byte-variant 'None')
        // streams into the signature-verification path and surfaces as InvalidSignature,
        // which is the wrong category — the cryptographic check never had a chance to run
        // because the algorithm itself is unrecognised.
        if (!SigningAlgorithms.Known.Contains(algorithm))
        {
            return new JwtValidationError(
                JwtError.InvalidAlgorithm,
                $"Unknown signing algorithm '{algorithm}' (RFC 7515 §5.3 byte-exact comparison).");
        }

        // Optional caller-supplied algorithm whitelist. Enforced before any other
        // alg-related branching so policy violations get a specific error rather than
        // routing through the (looser) signer-resolution failure path.
        if (parameters.AllowedSigningAlgorithms is { Count: > 0 } whitelist
            && !whitelist.Contains(algorithm))
        {
            return new JwtValidationError(
                JwtError.InvalidAlgorithm,
                $"Algorithm '{algorithm}' is not in the allowed signing algorithms.");
        }

        // 'alg' is byte-exact per RFC 7515 §5.3 / §10.13: switching on the const string ensures
        // case-variants like "None"/"NONE" never match the unsecured-JWS branch.
        switch (algorithm)
        {
            case SigningAlgorithms.None when parameters.Options.HasFlag(ValidationOptions.RequireSignedTokens):
                return new JwtValidationError(
                    JwtError.InvalidAlgorithm, "Unsigned tokens are not allowed");

            case SigningAlgorithms.None when jwtParts[2].HasValue():
                return new JwtValidationError(
                    JwtError.MalformedToken, "Unsigned token must have empty signature");

            case not SigningAlgorithms.None
                when parameters.Options.HasAnyFlag(ValidationOptions.RequireSignedTokens | ValidationOptions.ValidateIssuerSigningKey):
                break;

            default:
                return null;
        }

        // Two trust-model branches selected by the caller via UseEmbeddedVerificationKey:
        // either the JOSE header's 'jwk' is the signing key (DPoP-style proofs), or the
        // payload's 'iss' selects keys via the resolver delegate (id_token-style flows).
        // The selection is binary; mixing leads to attacker-controlled trust escalation.
        return parameters.Options.HasFlag(ValidationOptions.UseEmbeddedVerificationKey)
            ? await ValidateEmbeddedKeyAsync(token, jwtParts)
            : await ValidateIssuerSignatureAsync(token, jwtParts, parameters);
    }

    /// <summary>
    /// Verifies the JWS signature against the key embedded in the JOSE header's <c>jwk</c>
    /// parameter. This is the trust model RFC 9449 §4.2 prescribes for DPoP proofs — the
    /// proof carries its own public key and the validator's job is solely to confirm that
    /// the signature matches that key. The issuer-resolved-keys delegate is intentionally
    /// not consulted: in the embedded-key model there is no out-of-band key registry, so
    /// resolving by <c>iss</c> would either no-op or — worse — reintroduce the auto-trust
    /// surface this branch exists to keep closed.
    /// </summary>
    /// <param name="token">The parsed token; its <see cref="JsonWebTokenHeader.VerificationKey"/>
    /// supplies the candidate key.</param>
    /// <param name="jwtParts">The three compact-serialization segments
    /// (<c>header.payload.signature</c>) needed to recompute and compare the signature.</param>
    /// <returns><c>null</c> on success, or a <see cref="JwtValidationError"/> with
    /// <see cref="JwtError.InvalidHeader"/> when the <c>jwk</c> header is malformed or
    /// absent, or whatever category <see cref="IJsonWebTokenSigner.ValidateAsync"/> raises
    /// when the cryptographic check fails.</returns>
    private async Task<JwtValidationError?> ValidateEmbeddedKeyAsync(JsonWebToken token, string[] jwtParts)
    {
        JsonWebKey? embeddedJwk;
        try
        {
            embeddedJwk = token.Header.VerificationKey;
        }
        catch (JsonException)
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                $"Header '{JwtClaimTypes.JsonWebKeyHeader}' is not a valid JWK");
        }

        if (embeddedJwk is null)
        {
            return new JwtValidationError(
                JwtError.InvalidHeader,
                $"Header '{JwtClaimTypes.JsonWebKeyHeader}' is required when {nameof(ValidationOptions.UseEmbeddedVerificationKey)} is set");
        }

        return await signer.ValidateAsync(jwtParts, token.Header, embeddedJwk.ToAsync());
    }

    /// <summary>
    /// Verifies the JWS signature against the candidate-key set yielded by
    /// <see cref="ValidationParameters.ResolveIssuerSigningKeys"/> for the token's <c>iss</c>
    /// claim. This is the standard OIDC trust model: the host maintains an out-of-band
    /// mapping from issuer URL to its current signing JWKs (typically fetched from the
    /// issuer's <c>jwks_uri</c>) and the validator iterates that set looking for the key
    /// referenced by the JOSE header's <c>kid</c>.
    /// </summary>
    /// <param name="token">The parsed token; its <see cref="JsonWebTokenPayload.Issuer"/>
    /// is the lookup key for the resolver delegate.</param>
    /// <param name="jwtParts">The three compact-serialization segments
    /// (<c>header.payload.signature</c>) needed to recompute and compare the signature.</param>
    /// <param name="parameters">Validation parameters; <see cref="ValidationParameters.ResolveIssuerSigningKeys"/>
    /// must be configured for this branch and is dereferenced via
    /// <see cref="ObjectExtensions.NotNull{T}(T?, string)"/> so a missing resolver fails
    /// loud rather than silently accepting an unverifiable token.</param>
    /// <returns><c>null</c> on success, or a <see cref="JwtValidationError"/> with
    /// <see cref="JwtError.InvalidToken"/> when <c>iss</c> is missing, or whatever category
    /// <see cref="IJsonWebTokenSigner.ValidateAsync"/> raises (typically
    /// <see cref="JwtError.InvalidSignature"/>) when no resolved key verifies.</returns>
    private async Task<JwtValidationError?> ValidateIssuerSignatureAsync(
        JsonWebToken token,
        string[] jwtParts,
        ValidationParameters parameters)
    {
        var issuer = token.Payload.Issuer;
        if (issuer == null)
        {
            return new JwtValidationError(
                JwtError.InvalidToken, "Missing issuer in JWT payload for signature validation");
        }

        var resolveIssuerSigningKeys = parameters.ResolveIssuerSigningKeys
            .NotNull(nameof(parameters.ResolveIssuerSigningKeys));

        return await signer.ValidateAsync(jwtParts, token.Header, resolveIssuerSigningKeys(issuer));
    }

    /// <summary>
    /// Validates the JWS 'crit' header parameter (RFC 7515 §4.1.11). When present, every name in
    /// the array MUST be a non-standard JOSE header parameter name that is also present in the
    /// JOSE header and that the host has registered an <see cref="ICriticalHeaderHandler"/> for.
    /// Empty 'crit', duplicates, standard header names, dangling references, and unknown
    /// extension names all cause rejection.
    /// </summary>
    private JwtValidationError? ValidateCriticalHeaders(JsonWebTokenHeader header)
    {
        IReadOnlyList<string>? crit;
        try
        {
            crit = header.Critical;
        }
        catch (JsonException)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                "Invalid 'crit' header: must be a JSON array of strings");
        }

        if (crit is null)
            return null;

        if (crit.Count == 0)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                "'crit' header must not be the empty array (RFC 7515 §4.1.11)");
        }

        var distinctNames = new HashSet<string>(crit, StringComparer.Ordinal);
        if (distinctNames.Count != crit.Count)
            return new JwtValidationError(JwtError.InvalidToken, "'crit' header contains duplicate names");

        foreach (var name in crit)
        {
            if (ReservedCriticalHeaderNames.Contains(name))
            {
                return new JwtValidationError(
                    JwtError.InvalidToken,
                    $"'crit' header must not list standard JOSE header name: {name}");
            }

            if (!header.Json.ContainsKey(name))
            {
                return new JwtValidationError(
                    JwtError.InvalidToken,
                    $"'crit' lists header name '{name}' that is not present in the JOSE header");
            }

            var handler = serviceProvider.GetKeyedService<ICriticalHeaderHandler>(name);
            if (handler is null)
            {
                return new JwtValidationError(
                    JwtError.InvalidToken,
                    $"Unknown critical header parameter: {name}");
            }
        }

        return null;
    }

    /// <summary>
    /// Decrypts a JWE token and validates the inner JWT.
    /// </summary>
    private async Task<Result<JsonWebToken, JwtValidationError>> DecryptJweAsync(
        string[] jwtParts,
        ValidationParameters parameters)
    {
        // A JWE-shaped input where the caller didn't wire a decryption-key resolver is a
        // category error in this validator's contract: most callsites validate JWS only
        // (DPoP proofs per RFC 9449 §4.2, client_assertion per RFC 7521, etc.), and
        // throwing an unhandled InvalidOperationException turns a malformed-input case
        // into a 500 for the caller and a noisy server log. Surface the same outcome as a
        // typed validation error so the inbound payload gets rejected gracefully.
        var resolveTokenDecryptionKeys = parameters.ResolveTokenDecryptionKeys;
        if (resolveTokenDecryptionKeys is null)
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Received a JWE-shaped token (5 segments) but no decryption keys are configured for this validation path.");
        }
        var decryptionKeys = resolveTokenDecryptionKeys(string.Empty);

        var result = await encryptor.DecryptAsync(jwtParts, decryptionKeys);
        return await result.BindAsync(innerJwt => ValidateAsync(innerJwt, parameters));
    }

    /// <summary>
    /// Pins the JWT's <c>typ</c> header (RFC 7515 §4.1.9) to the set the caller expects, per
    /// the RFC 8725 §3.11 token-class-confusion guidance. When
    /// <see cref="ValidationParameters.ExpectedTokenTypes"/> is null or empty the check is
    /// skipped (backward-compatible default for callers that have not opted in). Comparison
    /// is case-sensitive per RFC 7515 §5.3, with the <c>application/</c> prefix stripped
    /// before lookup per the §4.1.9 convention so <c>typ=at+jwt</c> and
    /// <c>typ=application/at+jwt</c> both match a registered <c>at+jwt</c> expectation.
    /// </summary>
    private static JwtValidationError? ValidateTokenType(JsonWebTokenHeader header, ValidationParameters parameters)
    {
        if (parameters is not { ExpectedTokenTypes: { Count: > 0 } expected})
            return null;

        var typ = header.Type;
        if (typ is null)
        {
            return new JwtValidationError(
                JwtError.InvalidTokenType,
                $"JWT 'typ' header is missing — expected one of: {string.Join(", ", expected)}");
        }

        var normalized = StripApplicationPrefix(typ);
        if (!expected.Contains(normalized))
        {
            return new JwtValidationError(
                JwtError.InvalidTokenType,
                $"JWT 'typ' header '{typ}' does not match expected token type(s): {string.Join(", ", expected)}");
        }

        return null;

    }

    /// <summary>
    /// Implements RFC 7515 §4.1.9's prefix-stripping convention: when <c>typ</c> contains no
    /// '/' the recipient SHOULD treat it as if <c>application/</c> were prepended; symmetric
    /// stripping of the literal prefix lets either form match.
    /// </summary>
    private static string StripApplicationPrefix(string typ)
    {
        const string prefix = "application/";
        return typ.StartsWith(prefix, StringComparison.Ordinal) ? typ[prefix.Length..] : typ;
    }

    /// <summary>
    /// Validates the issuer claim according to validation parameters.
    /// </summary>
    private static async Task<JwtValidationError?> ValidateIssuerAsync(string? issuer, ValidationParameters parameters)
    {
        if (issuer != null)
        {
            if (parameters.Options.HasAnyFlag(ValidationOptions.RequireIssuer | ValidationOptions.ValidateIssuer))
            {
                var validateIssuer = parameters.ValidateIssuer.NotNull(nameof(parameters.ValidateIssuer));

                if (!await validateIssuer(issuer))
                    return new JwtValidationError(JwtError.InvalidToken, $"Invalid issuer: {issuer}");
            }
        }
        else if (parameters.Options.HasFlag(ValidationOptions.RequireIssuer))
        {
            return new JwtValidationError(JwtError.InvalidToken, "Missing issuer in JWT payload");
        }

        return null;
    }

    /// <summary>
    /// Validates the audience claim according to validation parameters.
    /// </summary>
    private static async Task<JwtValidationError?> ValidateAudienceAsync(
        IEnumerable<string> audiences,
        ValidationParameters parameters)
    {
        var audiencesList = audiences.ToList();

        if (parameters.Options.HasFlag(ValidationOptions.RequireAudience) && audiencesList.Count == 0)
            return new JwtValidationError(JwtError.InvalidToken, "Missing audience in JWT payload");

        if (parameters.Options.HasAnyFlag(ValidationOptions.RequireAudience | ValidationOptions.ValidateAudience) && audiencesList.Count > 0)
        {
            var validateAudience = parameters.ValidateAudience.NotNull(nameof(parameters.ValidateAudience));
            if (!await validateAudience(audiencesList))
            {
                return new JwtValidationError(
                    JwtError.InvalidToken, $"Invalid audience: {string.Join(", ", audiencesList)}");
            }
        }

        return null;
    }

    /// <summary>
    /// Validates the lifetime claims (nbf and exp) according to validation parameters.
    /// </summary>
    private JwtValidationError? ValidateLifetime(JsonWebTokenPayload payload, ValidationParameters parameters)
    {
        if (!parameters.Options.HasFlag(ValidationOptions.ValidateLifetime))
            return null;

        var notBefore = payload.NotBefore;
        var expiresAt = payload.ExpiresAt;
        if (!notBefore.HasValue && !expiresAt.HasValue)
            return null;

        var utcNow = timeProvider.GetUtcNow();

        if (notBefore.HasValue)
        {
            var notBeforeUtc = notBefore.Value.ToUniversalTime();
            if (utcNow.Add(parameters.ClockSkew) < notBeforeUtc)
                return new JwtValidationError(JwtError.InvalidToken, "Token not yet valid");
        }

        if (expiresAt.HasValue)
        {
            var expiresUtc = expiresAt.Value.ToUniversalTime();
            if (expiresUtc <= utcNow.Subtract(parameters.ClockSkew))
                return new JwtValidationError(JwtError.InvalidToken, "Token has expired");
        }

        return null;
    }

}
