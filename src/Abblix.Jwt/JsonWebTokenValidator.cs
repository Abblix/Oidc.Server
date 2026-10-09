// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;

using System.Buffers.Text;

namespace Abblix.Jwt;

/// <summary>
/// Represents a validator for JSON Web Tokens (JWTs) which validates a JWT against specified validation parameters.
/// </summary>
/// <param name="timeProvider">Provides access to the current time for lifetime validation.</param>
/// <param name="encryptor">The JWE encryptor for decrypting encrypted tokens.</param>
/// <param name="signer">The JWS signer for validating signatures.</param>
/// <param name="signingAlgorithmsProvider">The provider for supported signing algorithms.</param>
/// <param name="encryptionAlgorithmsProvider">The provider for supported JWE encryption algorithms.</param>
/// <param name="serviceProvider">Resolves registered <see cref="ICriticalHeaderHandler"/>
/// instances by JWS 'crit' header name (RFC 7515 section 4.1.11). Handlers are registered as keyed
/// singletons via <see cref="ServiceCollectionExtensions.AddCriticalHeaderHandler{THandler}"/>;
/// the validator routes a 'crit' name to its handler with
/// <c>GetKeyedService&lt;ICriticalHeaderHandler&gt;(name)</c> at validation time. With no
/// handler registered (the default) the library understands no crit extensions and rejects
/// every well-formed 'crit' header.</param>
internal class JsonWebTokenValidator(
    TimeProvider timeProvider,
    IJsonWebTokenEncryptor encryptor,
    IJsonWebTokenSigner signer,
    SigningAlgorithmsProvider signingAlgorithmsProvider,
    EncryptionAlgorithmsProvider encryptionAlgorithmsProvider,
    IServiceProvider serviceProvider) : IJsonWebTokenValidator
{
    private readonly JwsSignatureValidator _signatureValidator = new(signer);
    private readonly JwsCriticalHeaderValidator _criticalHeaderValidator = new(serviceProvider);

    /// <summary>
    /// Provides a collection of signing algorithms supported by the validator.
    /// Dynamically determined from registered signers in the dependency injection container.
    /// </summary>
    public IEnumerable<string> SigningAlgorithmsSupported => signingAlgorithmsProvider.Algorithms;

    /// <summary>
    /// Provides the JWE key-management algorithms (the <c>alg</c> values) the validator can decrypt.
    /// Dynamically determined from registered key encryptors in the dependency injection container.
    /// </summary>
    public IEnumerable<string> EncryptionAlgorithmsSupported => encryptionAlgorithmsProvider.KeyManagementAlgorithms;

    /// <summary>
    /// Provides the JWE content-encryption algorithms (the <c>enc</c> values) the validator can decrypt.
    /// Dynamically determined from registered content encryptors in the dependency injection container.
    /// </summary>
    public IEnumerable<string> EncryptionMethodsSupported => encryptionAlgorithmsProvider.ContentEncryptionAlgorithms;

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
        // Refused before the token is read: a validation that names no token types is a host's mistake rather than a
        // property of the token
        if (parameters.TokenTypes is null)
        {
            throw new ArgumentException(
                $"{nameof(ValidationParameters)}.{nameof(ValidationParameters.TokenTypes)} must name the token types " +
                "this validation accepts.",
                nameof(parameters));
        }

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
    /// Validates a JWS token from string parts. Each stage in the Bind chain either passes
    /// the token through unchanged (success) or short-circuits the rest of the chain with
    /// its <see cref="JwtValidationError"/>. Stages are ordered cheapest-and-most-categorical
    /// first (signature, then header-level checks, then payload-level checks) so a malformed
    /// or attacker-supplied token is rejected before any host-supplied callback is invoked.
    /// </summary>
    private Task<Result<JsonWebToken, JwtValidationError>> ValidateJwsAsync(string[] jwtParts, ValidationParameters parameters)
        => ParseJws(jwtParts)
            .Bind(token => JwsSignatureValidator.ValidateAlgorithm(token, parameters))
            .BindAsync(token => _signatureValidator.ValidateSignatureAsync(token, jwtParts, parameters))
            .BindAsync(token => _criticalHeaderValidator.ValidateAsync(token, parameters))
            .Bind(token => ValidateTokenType(token, parameters))
            .BindAsync(token => ValidateIssuerAsync(token, parameters))
            .BindAsync(token => ValidateAudienceAsync(token, parameters))
            .Bind(token => ValidateLifetime(token, parameters));

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
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWT format: base64url decoding failed");
        }

        if (!TryParseJsonObject(headerPart, out var headerObject))
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWS header: must be a JSON object");
        }

        if (!TryParseJsonObject(payloadPart, out var payloadObject))
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWS payload: must be a JSON object");
        }

        var token = new JsonWebToken
        {
            Header = new (headerObject),
            Payload = new (payloadObject),
        };

        return token;
    }

    private static bool TryParseJsonObject(byte[] jwtPart, [NotNullWhen(true)] out JsonObject? jsonObject)
    {
        try
        {
            var json = Encoding.UTF8.GetString(jwtPart);
            jsonObject = JsonNode.Parse(json, documentOptions: RejectRepeatedMemberNames) as JsonObject;
        }
        catch (JsonException)
        {
            jsonObject = null;
        }
        return jsonObject is not null;
    }

    /// <summary>
    /// Makes the parser itself reject a repeated member name, which is the first of the two options
    /// RFC 7519 Section 4 and RFC 7515 Section 4 allow a recipient. It reports the repetition as a
    /// <see cref="JsonException"/> at parse time, alongside every other malformed-JSON verdict.
    /// </summary>
    private static readonly JsonDocumentOptions RejectRepeatedMemberNames = new()
    {
        AllowDuplicateProperties = false,
    };

    /// <summary>
    /// Decrypts a JWE token and validates the inner JWT.
    /// </summary>
    private async Task<Result<JsonWebToken, JwtValidationError>> DecryptJweAsync(
        string[] jwtParts,
        ValidationParameters parameters)
    {
        // The token may be a perfectly well-formed JWE - the failure mode here is that
        // this validation path was not wired with a decryption-key resolver. Most callsites
        // validate JWS only (DPoP proofs per RFC 9449 section 4.2, client_assertion per RFC 7521,
        // etc.) and intentionally pass ResolveTokenDecryptionKeys = null. Throwing
        // InvalidOperationException from .NotNull turns a category mismatch into a 500
        // and a noisy server log; return a typed validation error instead so the caller
        // can map it onto the right HTTP error.
        var resolveTokenDecryptionKeys = parameters.ResolveTokenDecryptionKeys;
        if (resolveTokenDecryptionKeys is null)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                "Received a JWE-encrypted token but no decryption keys are configured for this validation path; this endpoint accepts JWS only.");
        }
        var decryptionKeys = resolveTokenDecryptionKeys(string.Empty);

        var result = await encryptor.DecryptAsync(jwtParts, decryptionKeys);
        // DecryptAsync is byte-oriented; the inner JWS is UTF-8 text, so decode it before re-validating.
        return await result.BindAsync(innerJwtBytes => ValidateAsync(Encoding.UTF8.GetString(innerJwtBytes), parameters));
    }

    /// <summary>
    /// Pins the JWT's <c>typ</c> header (RFC 7515 section 4.1.9) to the types the caller accepts, per
    /// the RFC 8725 section 3.11 token-type confusion guidance, as <see cref="ValidationParameters.TokenTypes"/>
    /// states them.
    /// </summary>
    /// <remarks>
    /// Matching is case-insensitive, and the <c>application/</c> prefix is stripped from the
    /// expectation as well as from the token, so either form may be written on either side.
    /// A <c>typ</c> is a media type: RFC 7515 section 4.1.9 says "Per RFC 2045, all media type values,
    /// subtype values, and parameter names are case insensitive", and RFC 2045 section 5.1 puts it
    /// flatly - "Matching of media type and subtype is ALWAYS case-insensitive". The same
    /// section 4.1.9 requires a recipient to treat a value without a '/' as if <c>application/</c>
    /// were prepended, which makes the short and long forms one name rather than two.
    /// Note that RFC 7515 section 5.3 does NOT apply here despite defining the library's general
    /// string-comparison rules: it ends by exempting exactly this parameter, "Only the 'typ'
    /// and 'cty' member values defined in this specification do not use these comparison
    /// rules".
    /// Folding costs no separation between the classes actually pinned here (<c>dpop+jwt</c>,
    /// <c>at+jwt</c>, <c>logout+jwt</c>): they differ in their letters, not
    /// their casing. The one place RFC 2045 keeps case significant is the value of a
    /// <c>;parameter=</c> tail, which no <c>typ</c> in these specifications carries; should one
    /// ever appear, this whole-string fold would be more permissive than the RFC on that tail.
    /// </remarks>
    private static Result<JsonWebToken, JwtValidationError> ValidateTokenType(
        JsonWebToken token, ValidationParameters parameters)
    {
        var policy = parameters.TokenTypes;
        var typ = token.Header.Type;
        return policy.Rule switch
        {
            TokenTypeRule.CheckedByCaller => token,
            TokenTypeRule.OrUntyped when typ is null => token,
            TokenTypeRule.Exactly when typ is null => new JwtValidationError(
                JwtError.InvalidTokenType,
                $"JWT 'typ' header is missing - expected one of: {string.Join(", ", policy.Types)}"),
            TokenTypeRule.Exactly or TokenTypeRule.OrUntyped =>
                policy.Types.Any(expected => JwtTypeName.Matches(typ, expected))
                    ? token
                    : new JwtValidationError(
                        JwtError.InvalidTokenType,
                        $"JWT 'typ' header '{typ}' does not match expected token type(s): " +
                        string.Join(", ", policy.Types)),
            _ => throw new InvalidOperationException(
                $"Unknown {nameof(TokenTypeRule)} value {policy.Rule}."),
        };
    }

    /// <summary>
    /// Validates the issuer claim according to validation parameters.
    /// </summary>
    private static async Task<Result<JsonWebToken, JwtValidationError>> ValidateIssuerAsync(
        JsonWebToken token, ValidationParameters parameters)
    {
        var issuer = token.Payload.Issuer;

        if (issuer is null)
        {
            return parameters.Options.HasFlag(ValidationOptions.RequireIssuer)
                ? new JwtValidationError(JwtError.InvalidToken, "Missing issuer in JWT payload")
                : token;
        }

        // Presence and validity are separate questions gated by separate flags, the same split
        // ValidateLifetime and RequireExpirationTime already use: RequireIssuer says iss has to be there,
        // ValidateIssuer says the one that is there must satisfy the caller's delegate. Reading either flag
        // as "run the delegate" made the documented use of RequireIssuer on its own throw instead of
        // validating.
        if (!parameters.Options.HasFlag(ValidationOptions.ValidateIssuer))
            return token;

        // The same category of mismatch as a missing key resolver, and answered the same way: the caller
        // asked for the issuer to be checked and wired nothing to check it with, which is a misconfiguration
        // this token cannot survive - but it is the token that fails, not the process. An
        // InvalidOperationException here would reach the host as a 500 on a request that deserves a refusal.
        if (parameters.ValidateIssuer is not { } validateIssuer)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                $"No issuer validator configured: {nameof(ValidationOptions.ValidateIssuer)} is set but "
                + $"{nameof(ValidationParameters.ValidateIssuer)} was not supplied.");
        }

        return await validateIssuer(issuer)
            ? token
            : new JwtValidationError(JwtError.InvalidToken, $"Invalid issuer: {issuer}");
    }

    /// <summary>
    /// Validates the audience claim according to validation parameters.
    /// </summary>
    private static async Task<Result<JsonWebToken, JwtValidationError>> ValidateAudienceAsync(
        JsonWebToken token, ValidationParameters parameters)
    {
        var audiencesList = token.Payload.Audiences.ToList();

        if (audiencesList.Count == 0)
        {
            return parameters.Options.HasFlag(ValidationOptions.RequireAudience)
                ? new JwtValidationError(JwtError.InvalidToken, "Missing audience in JWT payload")
                : token;
        }

        // The same split as the issuer above, and corrected in the same change because it was the same
        // defect one method down: requiring aud to be present said nothing about who may check it.
        if (!parameters.Options.HasFlag(ValidationOptions.ValidateAudience))
            return token;

        if (parameters.ValidateAudience is not { } validateAudience)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                $"No audience validator configured: {nameof(ValidationOptions.ValidateAudience)} is set but "
                + $"{nameof(ValidationParameters.ValidateAudience)} was not supplied.");
        }

        return await validateAudience(audiencesList)
            ? token
            : new JwtValidationError(JwtError.InvalidToken, $"Invalid audience: {string.Join(", ", audiencesList)}");
    }

    /// <summary>
    /// Validates the lifetime claims (nbf and exp) according to validation parameters.
    /// </summary>
    /// <remarks>
    /// Presence and value are two separate questions here, gated by two separate flags, the same
    /// way <see cref="ValidationOptions.RequireIssuer"/> and <see cref="ValidationOptions.ValidateIssuer"/>
    /// split them. The distinction is not academic: a token carrying neither <c>nbf</c> nor
    /// <c>exp</c> has no instant at which it is expired, so a pure lifetime comparison finds
    /// nothing wrong with it and lets it through forever. Whether that is correct depends
    /// entirely on the token type, which only the caller knows -
    /// <see cref="ValidationOptions.RequireExpirationTime"/> is how it says so.
    /// </remarks>
    private Result<JsonWebToken, JwtValidationError> ValidateLifetime(
        JsonWebToken token, ValidationParameters parameters)
    {
        var requireExpiration = parameters.Options.HasFlag(ValidationOptions.RequireExpirationTime);
        var validateLifetime = parameters.Options.HasFlag(ValidationOptions.ValidateLifetime);

        // Neither flag set means the claims are not this caller's business, so they are not read
        // at all: a caller who opted out of time handling is not told the token's dates are wrong.
        if (!requireExpiration && !validateLifetime)
            return token;

        // A timestamp the payload cannot read is the token's fault, not this server's, so it is
        // refused rather than allowed to escape as an exception out of the request. The token itself
        // parsed, which is why this is an invalid claim and not a malformed token.
        if (!token.Payload.TryReadTimestamps(out var notBefore, out var expiresAt, out var issuedAt, out var whyUnreadable))
            return new JwtValidationError(JwtError.InvalidToken, whyUnreadable);

        if (requireExpiration && !expiresAt.HasValue)
            return new JwtValidationError(JwtError.InvalidToken, "Missing expiration time in JWT payload");

        if (!validateLifetime)
            return token;

        if (!notBefore.HasValue && !expiresAt.HasValue && !issuedAt.HasValue)
            return token;

        return CompareTimestamps(token, parameters, notBefore, expiresAt, issuedAt);
    }

    /// <summary>
    /// Compares the three timestamps a token may carry against this server's clock, in the order a
    /// sender needs to hear about them.
    /// </summary>
    /// <remarks>
    /// The order is a decision, not an accident. A token carrying both <c>nbf</c> and <c>iat</c>
    /// ahead of this clock is post-dated, and "not yet valid" is what its sender needs to hear;
    /// answering about <c>iat</c> there would change which reason a caller is given for a refusal
    /// that already existed.
    ///
    /// Only the future direction of <c>iat</c> is checked. An <c>iat</c> in the past says nothing on
    /// its own: how old a token may be is a question about the token's kind, which the caller
    /// answers with <c>exp</c> or with its own maximum age, and answering it here would refuse every
    /// long-lived token this validator also serves. An <c>iat</c> ahead of this clock is not open
    /// the same way, because the token claims to have been created at an instant that has not
    /// happened.
    /// </remarks>
    private Result<JsonWebToken, JwtValidationError> CompareTimestamps(
        JsonWebToken token,
        ValidationParameters parameters,
        DateTimeOffset? notBefore,
        DateTimeOffset? expiresAt,
        DateTimeOffset? issuedAt)
    {
        var utcNow = timeProvider.GetUtcNow();

        // Whatever bound the caller is held to has already been applied to the value it handed
        // over: a ceiling arriving as a second field is a ceiling somebody forgets to pass, and the
        // omission would read as a caller entitled to be looser rather than as the mistake it is.
        var refusal = parameters.ClockSkew.WhyRefused(utcNow, notBefore, expiresAt, issuedAt);

        return refusal is null
            ? token
            : new JwtValidationError(JwtError.InvalidToken, refusal);
    }

}
