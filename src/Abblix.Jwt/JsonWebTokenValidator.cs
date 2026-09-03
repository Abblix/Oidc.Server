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
            .BindAsync(token => ValidateSignatureAsync(token, jwtParts, parameters))
            .BindAsync(token => ValidateCriticalHeadersAsync(token, parameters))
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
#if NET10_0_OR_GREATER
            jsonObject = JsonNode.Parse(json, documentOptions: RejectRepeatedMemberNames) as JsonObject;
#else
            jsonObject = HasRepeatedMemberName(jwtPart) ? null : JsonNode.Parse(json) as JsonObject;
#endif
        }
        catch (JsonException)
        {
            jsonObject = null;
        }
        return jsonObject is not null;
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Makes the parser itself reject a repeated member name, which is the first of the two options
    /// RFC 7519 Section 4 and RFC 7515 Section 4 allow a recipient. It reports the repetition as a
    /// <see cref="JsonException"/> at parse time, alongside every other malformed-JSON verdict.
    /// </summary>
    private static readonly JsonDocumentOptions RejectRepeatedMemberNames = new()
    {
        AllowDuplicateProperties = false,
    };
#else
    /// <summary>
    /// Reports whether any JSON object in <paramref name="json"/> names the same member twice, at any depth.
    /// </summary>
    /// <remarks>
    /// This is the pre-net10 stand-in for <c>JsonDocumentOptions.AllowDuplicateProperties</c>. Left to itself,
    /// <see cref="JsonNode"/> neither rejects a repeated name nor keeps only the lexically last one, which are
    /// the two outcomes the specifications allow. It builds its members lazily, so the repetition is not a parse
    /// error at all: the parse reports success and the duplicate surfaces later as an
    /// <see cref="ArgumentException"/> from whichever property the caller reads first, or, for a duplicate nested
    /// inside a structured claim that validation never reads, not until the token has already been accepted and
    /// handed on. The input is attacker-supplied, so the scan runs ahead of the parse.
    /// </remarks>
    private static bool HasRepeatedMemberName(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(json);
        var namesByDepth = new Stack<HashSet<string>>();

        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    namesByDepth.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;

                case JsonTokenType.EndObject:
                    namesByDepth.Pop();
                    break;

                case JsonTokenType.PropertyName when !namesByDepth.Peek().Add(reader.GetString()!):
                    return true;
            }
        }

        return false;
    }
#endif

    /// <summary>
    /// Validates the JWS signature according to validation parameters. Returns the token
    /// unchanged on success - the chain stage adds nothing to the token, only gates the
    /// rest of the pipeline behind a successful integrity proof.
    /// </summary>
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateSignatureAsync(
        JsonWebToken token,
        string[] jwtParts,
        ValidationParameters parameters)
    {
        // Per RFC 7515 Section 4.1.1, 'alg' parameter is REQUIRED
        var algorithm = token.Header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidAlgorithm, "Missing algorithm in JWT header");

        // Reject anything outside the registered RFC 7518 section 3 alg taxonomy with the matching
        // taxonomy-level error. Without this gate, an unknown alg (e.g. byte-variant 'None')
        // streams into the signature-verification path and surfaces as InvalidSignature,
        // which is the wrong category - the cryptographic check never had a chance to run
        // because the algorithm itself is unrecognised.
        if (!SigningAlgorithms.Known.Contains(algorithm))
        {
            return new JwtValidationError(
                JwtError.InvalidAlgorithm,
                $"Unknown signing algorithm '{algorithm}' (RFC 7515 section 5.3 byte-exact comparison).");
        }

        // Ahead of the allowlist, because an unsigned token is refused for BEING unsigned rather than
        // for being absent from a list it can never appear in: any caller whose allowlist is a policy
        // rejects "none" from it, so leaving this arm behind the list left it unreachable for every
        // caller that supplies one - and answered the alg:none downgrade with "not in the allowed
        // signing algorithms", which reads as an invitation to widen the list until it fits.
        if (algorithm == SigningAlgorithms.None
            && parameters.Options.HasFlag(ValidationOptions.RequireSignedTokens))
        {
            return new JwtValidationError(JwtError.InvalidAlgorithm, "Unsigned tokens are not allowed");
        }

        // Optional caller-supplied algorithm whitelist, checked before the signer is resolved so a
        // policy violation gets its own error rather than the looser signer-resolution failure.
        //
        // The accepted set is named HERE because this is the only place the cause is known:
        // JwtError.InvalidAlgorithm carries four different failures - a missing alg, one outside
        // the RFC 7518 taxonomy, this policy refusal, and an unsigned token where signatures are
        // required - so a caller branching on the category cannot tell which it met. One that
        // guesses advises widening an allowlist over a token that names no algorithm at all.
        if (parameters.AllowedSigningAlgorithms is { Count: > 0 } whitelist
            && !whitelist.Contains(algorithm))
        {
            return new JwtValidationError(
                JwtError.InvalidAlgorithm,
                $"Algorithm '{algorithm}' is not in the allowed signing algorithms, which are "
                + $"{string.Join(", ", whitelist.Order(StringComparer.Ordinal))}.");
        }

        // 'alg' is byte-exact per RFC 7515 section 5.3 / section 10.13: switching on the const string ensures
        // case-variants like "None"/"NONE" never match the unsecured-JWS branch.
        return algorithm switch
        {
            SigningAlgorithms.None when jwtParts[2].HasValue()
                => new JwtValidationError(JwtError.MalformedToken, "Unsigned token must have empty signature"),

            // Reached only by alg "none" when signatures are not required - accept the unsigned token.
            SigningAlgorithms.None => token,

            // Two trust-model branches selected by the caller via UseEmbeddedVerificationKey:
            // either the JOSE header's 'jwk' is the signing key (DPoP-style proofs), or the
            // payload's 'iss' selects keys via the resolver delegate (id_token-style flows).
            // The selection is binary; mixing leads to attacker-controlled trust escalation.
            _ when parameters.Options.HasFlag(ValidationOptions.UseEmbeddedVerificationKey)
                => await ValidateEmbeddedKeyAsync(token, jwtParts),

            _ => await ValidateIssuerSignatureAsync(token, jwtParts, parameters)
        };
    }

    /// <summary>
    /// Verifies the JWS signature against the key embedded in the JOSE header's <c>jwk</c>
    /// parameter. This is the trust model RFC 9449 section 4.2 prescribes for DPoP proofs - the
    /// proof carries its own public key and the validator's job is solely to confirm that
    /// the signature matches that key. The issuer-resolved-keys delegate is intentionally
    /// not consulted: in the embedded-key model there is no out-of-band key registry, so
    /// resolving by <c>iss</c> would either no-op or - worse - reintroduce the auto-trust
    /// surface this branch exists to keep closed.
    /// </summary>
    /// <param name="token">The parsed token; its <see cref="JsonWebTokenHeader.VerificationKey"/>
    /// supplies the candidate key.</param>
    /// <param name="jwtParts">The three compact-serialization segments
    /// (<c>header.payload.signature</c>) needed to recompute and compare the signature.</param>
    /// <returns>The token unchanged on success; a <see cref="JwtValidationError"/> with
    /// <see cref="JwtError.InvalidHeader"/> when the <c>jwk</c> header is malformed or
    /// absent; or whatever category <see cref="IJsonWebTokenSigner.ValidateAsync"/> raises
    /// when the cryptographic check fails.</returns>
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateEmbeddedKeyAsync(
        JsonWebToken token, string[] jwtParts)
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

        var error = await signer.ValidateAsync(jwtParts, token.Header, embeddedJwk.ToAsync());
        return error is null ? token : error;
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
    /// <returns>The token unchanged on success; a <see cref="JwtValidationError"/> with
    /// <see cref="JwtError.InvalidToken"/> when <c>iss</c> is missing; or whatever category
    /// <see cref="IJsonWebTokenSigner.ValidateAsync"/> raises (typically
    /// <see cref="JwtError.InvalidSignature"/>) when no resolved key verifies.</returns>
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateIssuerSignatureAsync(
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

        // Symmetric with the JWE path: the validator's other trust mode looks up signing
        // keys by issuer (via parameters.ResolveIssuerSigningKeys, typically the host's
        // JWKS lookup). A caller routed here without wiring that delegate is a category
        // mismatch - surface a typed JwtValidationError so the request fails with a 401,
        // not an unhandled NotNull throw that propagates as 500.
        var resolveIssuerSigningKeys = parameters.ResolveIssuerSigningKeys;
        if (resolveIssuerSigningKeys is null)
        {
            return new JwtValidationError(
                JwtError.InvalidToken,
                "No signing-key resolver configured: this validation path expected to look up signing keys by 'iss' but the host did not provide ResolveIssuerSigningKeys.");
        }

        var error = await signer.ValidateAsync(jwtParts, token.Header, resolveIssuerSigningKeys(issuer));
        return error is null ? token : error;
    }

    /// <summary>
    /// Validates the JWS 'crit' header parameter (RFC 7515 section 4.1.11). Runs the spec-required
    /// malformation guards (empty array, duplicates, reserved names, dangling references)
    /// independent of any registry, then routes each crit name to its registered
    /// <see cref="ICriticalHeaderHandler"/>. An unrouted name is rejected as «unknown
    /// critical header parameter» per RFC 7515 section 4.1.11 ("If any of the listed extension
    /// Header Parameters are not understood and supported by the recipient, then the JWS
    /// is invalid").
    /// </summary>
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateCriticalHeadersAsync(
        JsonWebToken token,
        ValidationParameters parameters)
    {
        var structuralError = CriticalHeaderValidation.ValidateStructure(
            token.Header, CriticalHeaderValidation.JwsReservedNames, out var crit);

        if (structuralError is not null)
            return structuralError;

        // No 'crit' at all is the ordinary case and needs no handler pass.
        if (crit is null)
            return token;

        return await DispatchCritHandlersAsync(token, parameters, crit);
    }

    /// <summary>
    /// Resolves the registered handler for each crit-listed name (keyed by name in DI) and
    /// runs them in declaration order. Every name is resolved BEFORE any handler runs: per
    /// RFC 7515 section 4.1.11 an unknown name invalidates the whole JWS, so an earlier extension's
    /// side effects must never apply only to reject on a later unknown name. An unresolved
    /// name is rejected as «unknown critical header parameter».
    /// </summary>
    private async Task<Result<JsonWebToken, JwtValidationError>> DispatchCritHandlersAsync(
        JsonWebToken token,
        ValidationParameters parameters,
        IReadOnlyList<string> crit)
    {
        var handlers = new ICriticalHeaderHandler[crit.Count];
        for (var i = 0; i < crit.Count; i++)
        {
            if (serviceProvider.GetKeyedService<ICriticalHeaderHandler>(crit[i]) is not { } handler)
            {
                return new JwtValidationError(
                    JwtError.InvalidHeader,
                    $"Unknown critical header parameter: {crit[i]}");
            }

            handlers[i] = handler;
        }

        var context = new CriticalHeaderContext
        {
            Token = token,
            Parameters = parameters,
        };

        // The JWS validation pipeline does not thread a CancellationToken (see
        // IJsonWebTokenValidator.ValidateAsync), so none is available to propagate here.
        if (await handlers.FirstOrDefaultAsync(handler => handler.HandleAsync(context, CancellationToken.None)) is { } error)
            return error;

        return token;
    }

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
    /// Pins the JWT's <c>typ</c> header (RFC 7515 section 4.1.9) to the set the caller expects, per
    /// the RFC 8725 section 3.11 token-type confusion guidance. When
    /// <see cref="ValidationParameters.ExpectedTokenTypes"/> is null or empty the check is
    /// skipped (backward-compatible default for callers that have not opted in).
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
    /// rules". This code cited section 5.3 for the opposite conclusion until 2026-07-20.
    /// Folding costs no separation between the classes actually pinned here (<c>dpop+jwt</c>,
    /// <c>at+jwt</c>, <c>logout+jwt</c>, <c>id_token</c>): they differ in their letters, not
    /// their casing. The one place RFC 2045 keeps case significant is the value of a
    /// <c>;parameter=</c> tail, which no <c>typ</c> in these specifications carries; should one
    /// ever appear, this whole-string fold would be more permissive than the RFC on that tail.
    /// The comparison deliberately does not use <see cref="IReadOnlySet{T}.Contains"/>: the set
    /// arrives from the caller with a comparer of their choosing, which would quietly hand a
    /// security decision to host configuration this validator can neither see nor vouch for.
    /// </remarks>
    private static Result<JsonWebToken, JwtValidationError> ValidateTokenType(
        JsonWebToken token, ValidationParameters parameters)
    {
        if (parameters is not { ExpectedTokenTypes: { Count: > 0 } expected})
            return token;

        var typ = token.Header.Type;
        if (typ is null)
        {
            return new JwtValidationError(
                JwtError.InvalidTokenType,
                $"JWT 'typ' header is missing - expected one of: {string.Join(", ", expected)}");
        }

        var matched = expected.Any(expectedTyp => JwtTypeName.Matches(typ, expectedTyp));

        if (!matched)
        {
            return new JwtValidationError(
                JwtError.InvalidTokenType,
                $"JWT 'typ' header '{typ}' does not match expected token type(s): {string.Join(", ", expected)}");
        }

        return token;
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

        // Neither flag set means the claims are not this caller's business, and reading them is
        // not free of consequence: the accessors throw on a timestamp outside DateTimeOffset's
        // range, which a caller who opted out of time handling should never have to meet.
        if (!requireExpiration && !validateLifetime)
            return token;

        var notBefore = token.Payload.NotBefore;
        var expiresAt = token.Payload.ExpiresAt;

        if (requireExpiration && !expiresAt.HasValue)
            return new JwtValidationError(JwtError.InvalidToken, "Missing expiration time in JWT payload");

        if (!validateLifetime)
            return token;

        if (!notBefore.HasValue && !expiresAt.HasValue)
            return token;

        var utcNow = timeProvider.GetUtcNow();

        if (notBefore.HasValue)
        {
            var notBeforeUtc = notBefore.Value.ToUniversalTime();
            if (utcNow + parameters.ClockSkew < notBeforeUtc)
                return new JwtValidationError(JwtError.InvalidToken, "Token not yet valid");
        }

        if (expiresAt.HasValue)
        {
            var expiresUtc = expiresAt.Value.ToUniversalTime();
            if (expiresUtc <= utcNow - parameters.ClockSkew)
                return new JwtValidationError(JwtError.InvalidToken, "Token has expired");
        }

        return token;
    }

}
