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
using Abblix.Oidc.Client.Features.TokenValidation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.IdentityTokens;

/// <summary>
/// Validates an ID Token: the cryptography through <see cref="IJsonWebTokenValidator"/>, then the
/// claim rules OpenID Connect adds on top of a plain JWT.
/// </summary>
/// <remarks>
/// The split is not arbitrary. Everything a JOSE library can decide from the token alone - the
/// signature, the algorithm, the expiry - is decided by one, and everything that needs to know what
/// this client asked for is decided here. A nonce, a hash binding and a max_age are all comparisons
/// against a question the JWT layer never saw.
/// The order matters too: nothing is compared until the signature has been verified. Until then the
/// claims are attacker-supplied text, and a check run against them proves nothing about anybody.
/// </remarks>
/// <param name="tokenVerifier">Establishes that the token is the provider's and addressed to this client.</param>
/// <param name="clientOptions">Carries the client identifier that <c>azp</c> is matched against.</param>
/// <param name="options">Where the specification leaves a policy choice.</param>
/// <param name="providerTokenOptions">Carries the clock skew the age comparisons allow.</param>
/// <param name="timeProvider">Reads the current time for the age comparisons.</param>
internal sealed class IdentityTokenValidator(
    IProviderTokenVerifier tokenVerifier,
    IOptions<OidcClientOptions> clientOptions,
    IOptions<IdentityTokenValidationOptions> options,
    IOptions<ProviderTokenValidationOptions> providerTokenOptions,
    TimeProvider timeProvider) : IIdentityTokenValidator
{
    public async Task<JsonWebToken> ValidateAsync(
        string identityToken,
        IdentityTokenValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var clientId = clientOptions.Value.ClientId;
        var policy = options.Value;

        JsonWebToken token;
        try
        {
            token = await tokenVerifier.VerifyAsync(identityToken, cancellationToken);
        }
        catch (ProviderTokenValidationException exception)
        {
            throw new IdentityTokenValidationException(
                $"The ID Token was rejected: {exception.Message}");
        }

        // From here the token is signed by the issuer and addressed to this client, so its claims are
        // the issuer's statements rather than the sender's, and comparing them means something.
        RequireSubject(token);
        RequireExpiry(token);
        CheckIssuedAtAge(token, policy);
        CheckAuthorizedParty(token, clientId);
        CheckNonce(token, context);
        CheckBinding(token, JwtClaimTypes.CodeHash, token.Payload.CodeHash, context.AuthorizationCode);
        CheckBinding(token, JwtClaimTypes.AccessTokenHash, token.Payload.AccessTokenHash, context.AccessToken);
        CheckAuthenticationAge(token, context);
        CheckAuthenticationContextClass(token, context);

        return token;
    }

    /// <summary>
    /// Section 2 lists <c>sub</c> among the REQUIRED claims and bounds it: "It MUST NOT exceed 255
    /// ASCII characters in length."
    /// </summary>
    /// <remarks>
    /// An empty string passes a presence check and identifies nobody, so it is refused with the
    /// missing case rather than treated as a subject nobody can look up.
    /// </remarks>
    private static void RequireSubject(JsonWebToken token)
    {
        var subject = token.Payload.Subject;
        if (string.IsNullOrEmpty(subject))
            throw new IdentityTokenValidationException("The ID Token carries no subject.");

        if (subject.Length > 255)
            throw new IdentityTokenValidationException("The ID Token's subject exceeds 255 characters.");
    }

    /// <summary>
    /// Section 2 makes <c>exp</c> REQUIRED, and step 9 says the current time MUST be before it.
    /// </summary>
    /// <remarks>
    /// The comparison is the JWT layer's, but the presence is not: a token with no expiry has no
    /// instant at which it is expired, so a pure lifetime check finds nothing wrong and lets it stand
    /// forever. Asked here because only this layer knows the token is meant to be an ID Token.
    /// </remarks>
    private static void RequireExpiry(JsonWebToken token)
    {
        if (!token.Payload.ExpiresAt.HasValue)
            throw new IdentityTokenValidationException("The ID Token carries no expiration time.");
    }

    /// <summary>
    /// Step 10 permits rejecting a token issued too long ago, leaving the window to the client.
    /// </summary>
    private void CheckIssuedAtAge(JsonWebToken token, IdentityTokenValidationOptions policy)
    {
        if (policy.MaximumIssuedAtAge is not { } maximumAge)
            return;

        var issuedAt = token.Payload.IssuedAt;
        if (!issuedAt.HasValue)
            throw new IdentityTokenValidationException("The ID Token carries no issuance time to judge its age by.");

        if (timeProvider.GetUtcNow() - issuedAt.Value > maximumAge + providerTokenOptions.Value.ClockSkew)
            throw new IdentityTokenValidationException("The ID Token was issued too long ago.");
    }

    /// <summary>
    /// Steps 4 and 5: when an <c>azp</c> claim is present the client SHOULD verify that its own
    /// client identifier is the value.
    /// </summary>
    /// <remarks>
    /// Presence-conditional, and deliberately not the other way round. Section 2 makes the claim
    /// OPTIONAL, so requiring it would refuse conformant providers; but a present azp naming somebody
    /// else says the token was minted for a different party, and accepting that is what the check
    /// exists to stop.
    /// </remarks>
    private static void CheckAuthorizedParty(JsonWebToken token, string clientId)
    {
        var authorizedParty = token.Payload.AuthorizedParty;
        if (authorizedParty is null)
            return;

        if (!string.Equals(authorizedParty, clientId, StringComparison.Ordinal))
            throw new IdentityTokenValidationException("The ID Token names a different authorized party.");
    }

    /// <summary>
    /// Step 11: when the client sent a nonce, the value in the token MUST be the one it sent.
    /// </summary>
    /// <remarks>
    /// RFC 9700 section 4.5.3.2 adds the consequence in full: until this check succeeds, every token
    /// in the response - the access token included - must be disregarded. Throwing achieves that, as
    /// long as no caller reads anything out before calling.
    /// A client that sent no nonce has nothing to compare, and the claim is then not evidence of
    /// anything; it is neither required nor rejected.
    /// </remarks>
    private static void CheckNonce(JsonWebToken token, IdentityTokenValidationContext context)
    {
        if (context.Nonce is null)
            return;

        var nonce = token.Payload.Nonce;
        if (nonce is null)
            throw new IdentityTokenValidationException("The ID Token carries no nonce, but one was requested.");

        if (!string.Equals(nonce, context.Nonce, StringComparison.Ordinal))
            throw new IdentityTokenValidationException("The ID Token's nonce does not match the one sent.");
    }

    /// <summary>
    /// Verifies a detached-signature binding: <c>c_hash</c> against the authorization code, or
    /// <c>at_hash</c> against the access token (sections 3.3.2.10 and 3.2.2.9).
    /// </summary>
    /// <remarks>
    /// Checked whenever both halves are in hand. The specification makes performing it a SHOULD for
    /// the front channel and a MAY for the code flow, and only the comparison itself a MUST; this
    /// client always performs it, which is stricter than the text and is the point - a code or access
    /// token swapped in transit is exactly what the binding detects, and skipping the check for lack
    /// of an obligation would leave the swap undetected.
    /// A claim present with nothing to compare it to is not evidence and is left alone. The reverse -
    /// a value in hand and no claim - is also allowed, because the claim is REQUIRED of the issuer
    /// only when the token comes from the authorization endpoint, and refusing it elsewhere would
    /// reject conformant providers.
    /// </remarks>
    private static void CheckBinding(JsonWebToken token, string claimName, string? claimed, string? value)
    {
        if (claimed is null || value is null)
            return;

        var algorithm = token.Header.Algorithm;
        var expected = algorithm is null ? null : HashCalculator.Compute(algorithm, value);

        // No digest is paired with this algorithm, so the binding cannot be checked. That is not the
        // same as it holding, and treating the two alike would let a token signed with an algorithm
        // outside the JWA table carry any hash at all.
        if (expected is null)
        {
            throw new IdentityTokenValidationException(
                $"The ID Token's {claimName} cannot be verified: its algorithm has no hash defined.");
        }

        if (!string.Equals(claimed, expected, StringComparison.Ordinal))
            throw new IdentityTokenValidationException($"The ID Token's {claimName} does not match.");
    }

    /// <summary>
    /// Step 13: when the client asked with <c>max_age</c>, it SHOULD check <c>auth_time</c> and ask
    /// for re-authentication if too much time has passed.
    /// </summary>
    /// <remarks>
    /// Section 2 makes the claim REQUIRED of the issuer under exactly this condition, so its absence
    /// here is the provider ignoring the request rather than a claim this client failed to ask for.
    /// The specification prescribes re-authentication rather than rejection; this client rejects, and
    /// the caller re-authenticates, because a client library cannot start a login on its own and
    /// returning "valid" for a session older than was asked for would be the wrong default.
    /// </remarks>
    private void CheckAuthenticationAge(JsonWebToken token, IdentityTokenValidationContext context)
    {
        if (context.MaxAge is not { } maxAge)
            return;

        var authenticationTime = token.Payload.AuthenticationTime;
        if (!authenticationTime.HasValue)
        {
            throw new IdentityTokenValidationException(
                "The ID Token carries no authentication time, though max_age was requested.");
        }

        if (timeProvider.GetUtcNow() - authenticationTime.Value > maxAge + providerTokenOptions.Value.ClockSkew)
            throw new IdentityTokenValidationException("The end user was authenticated longer ago than max_age allows.");
    }

    /// <summary>
    /// Step 12: when the <c>acr</c> claim was requested, the client SHOULD check that the asserted
    /// value is appropriate.
    /// </summary>
    /// <remarks>
    /// "Appropriate" is the client's judgement, and the specification says the meaning of these values
    /// is out of its scope, so this compares against the set the caller supplied and nothing more.
    /// Core defines no ordering over acr values, so "weaker than requested" is not expressible; a
    /// value outside the accepted set is refused, a request that named no values checks nothing.
    /// </remarks>
    private static void CheckAuthenticationContextClass(JsonWebToken token, IdentityTokenValidationContext context)
    {
        var acceptable = context.AcceptableAuthenticationContextClassReferences;
        if (acceptable.Count == 0)
            return;

        var asserted = token.Payload.AuthContextClassRef;
        if (asserted is null || !acceptable.Contains(asserted, StringComparer.Ordinal))
        {
            throw new IdentityTokenValidationException(
                "The ID Token asserts an authentication context class this client does not accept.");
        }
    }
}
