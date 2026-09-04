// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Issuer;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Base class for JWT assertion-based client authenticators, providing common validation logic
/// for both private_key_jwt and client_secret_jwt authentication methods.
/// </summary>
/// <param name="logger">logger for recording the authentication process and any issues encountered.</param>
/// <param name="replayCache">Replay cache that records assertion jti values and atomically rejects reuse.</param>
/// <param name="issuerProvider">Supplies the issuer identifier a profile-governed assertion must name.</param>
/// <param name="options">Supplies the server-wide default security profile.</param>
/// <param name="timeProvider">Judges the assertion's timestamps against the client's own profile.</param>
public abstract partial class JwtAssertionAuthenticatorBase(
    ILogger logger,
    IReplayCache replayCache,
    IIssuerProvider issuerProvider,
    IOptions<OidcOptions> options,
    TimeProvider timeProvider) : IClientAuthenticator
{
    /// <summary>
    /// The clock this class judges an assertion's timestamps by, exposed so a derived authenticator
    /// reads the same instant rather than capturing a second copy of the same dependency.
    /// </summary>
    protected TimeProvider Clock => timeProvider;

    /// <summary>
    /// Specifies the client authentication methods supported by this authenticator.
    /// </summary>
    public abstract IEnumerable<string> ClientAuthenticationMethodsSupported { get; }

    /// <summary>
    /// The control bundle this deployment's default profile mandates, for a derived authenticator
    /// building its own validation parameters. Read from the same options this class validates
    /// against, so the two cannot disagree.
    /// </summary>
    protected SecurityProfileRequirements DefaultProfileRequirements
        => SecurityProfileRequirements.Resolve(options.Value.DefaultSecurityProfile);

    /// <summary>
    /// Answers whether the assertion's timestamps sit inside the window the profile governing THIS
    /// CLIENT allows, which the validator could not ask: the client is identified from the assertion
    /// it is validating, so its profile is not known until the validation has finished.
    /// </summary>
    /// <remarks>
    /// The first pass ran under the deployment's own window, which is the widest any client can be
    /// given - a deployment-wide profile is a floor and a client may only tighten it. So this
    /// narrows and never widens.
    ///
    /// Placed before the identifier is reserved, because a reservation is spent and cannot be given
    /// back: a refusal after it would burn the assertion's own identifier on a request this check
    /// was going to reject.
    /// </remarks>
    /// <param name="token">The assertion whose timestamps are being judged.</param>
    /// <param name="clientInfo">The client the assertion authenticates.</param>
    private bool TimestampsSatisfyTheClientsOwnProfile(JsonWebToken token, ClientInfo clientInfo)
    {
        var refusal = SecurityProfileRequirements
            .For(clientInfo, options.Value.DefaultSecurityProfile)
            .ClockSkewOrDefault()
            .WhyRefused(
                timeProvider.GetUtcNow(),
                token.Payload.NotBefore,
                token.Payload.ExpiresAt,
                token.Payload.IssuedAt);

        if (refusal is null)
            return true;

        LogTimestampsOutsideTheClientsProfile(clientInfo.ClientId, refusal);
        return false;
    }

    /// <summary>
    /// Answers whether the assertion's audience is one the profile governing this client admits.
    /// </summary>
    /// <remarks>
    /// FAPI 2.0 section 5.3.2.1 narrows what may stand there: a server held to the profile "shall
    /// only accept its issuer identifier value (as defined in [RFC8414]) as a string". Both halves
    /// matter. The value must be the issuer rather than any address this server answers on, and it
    /// must be alone rather than one entry among several, so an assertion minted for a different
    /// recipient cannot be replayed here by naming both. Outside the profile the wider reading the
    /// underlying specification permits is left untouched, which is why this answers true there
    /// rather than checking anything.
    /// </remarks>
    private bool AudienceSatisfiesTheProfile(JsonWebToken token, ClientInfo clientInfo)
    {
        if (!SecurityProfileRequirements.For(clientInfo, options.Value.DefaultSecurityProfile)
                .RequireIssuerAudienceInClientAssertion)
        {
            return true;
        }

        var issuerIdentifier = issuerProvider.GetIssuer();
        var audiences = token.Payload.Audiences.ToArray();
        if (audiences is [var onlyAudience] && onlyAudience == issuerIdentifier)
        {
            return true;
        }

        LogAudienceIsNotTheIssuerAlone(clientInfo.ClientId, audiences, issuerIdentifier);
        return false;
    }

    /// <summary>
    /// Attempts to authenticate a client using JWT assertion by validating the JWT provided in the client request.
    /// </summary>
    /// <param name="request">The client request containing the JWT to authenticate.</param>
    /// <returns>The authenticated <see cref="ClientInfo"/>, or null if authentication fails.</returns>
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        if (request.ClientAssertionType is null)
        {
            return null;
        }

        if (request.ClientAssertionType != ClientAssertionTypes.JwtBearer)
        {
            LogWrongAssertionType();
            return null;
        }

        if (!request.ClientAssertion.HasValue())
        {
            LogMissingAssertion();
            return null;
        }

        var validationResult = await ValidateJwtAsync(request.ClientAssertion);
        if (!validationResult.TryGetSuccess(out var validJwt))
        {
            var error = validationResult.GetFailure();
            LogJwtValidationError(error);
            return null;
        }

        var token = validJwt.Token;
        var clientInfo = validJwt.Client;

        var tokenEndpointAuthMethod = clientInfo.TokenEndpointAuthMethod;
        if (!ClientAuthenticationMethodsSupported.Contains(tokenEndpointAuthMethod.NotNull(nameof(tokenEndpointAuthMethod))))
        {
            LogAuthMethodNotAllowed(clientInfo.ClientId);
            return null;
        }

        // OIDC Core §9 / RFC 7591: when the client registered token_endpoint_auth_signing_alg, the
        // assertion MUST use exactly that algorithm. The signature is already verified by here; this
        // pins the registered algorithm so a client cannot authenticate with a different (e.g. weaker)
        // algorithm its key happens to support.
        var requiredSigningAlgorithm = clientInfo.TokenEndpointAuthSigningAlgorithm;
        if (requiredSigningAlgorithm.HasValue() &&
            !string.Equals(token.Header.Algorithm, requiredSigningAlgorithm, StringComparison.Ordinal))
        {
            LogSigningAlgorithmNotAllowed(clientInfo.ClientId, token.Header.Algorithm, requiredSigningAlgorithm);
            return null;
        }

        string? subject;
        try
        {
            subject = token.Payload.Subject;
        }
        catch (InvalidOperationException ex)
        {
            LogSubjectExtractionFailed(ex, ex.Message);
            return null;
        }

        var issuer = token.Payload.Issuer;
        if (issuer == null || subject == null || issuer != subject)
        {
            LogIssuerSubjectMismatch(issuer, subject);
            return null;
        }

        // An assertion authenticates the client; it is not a token this server issued. RFC 7523bis asks that
        // such a JWT be typed "client-authentication+jwt or another more specific explicit type value defined
        // by a specification profiling this specification" - a SHOULD on the sender, and one that admits
        // values we cannot list, so the exact value cannot be demanded. What can be refused is a JWT declaring
        // itself some other type this class names, which is the replay RFC 8725 §3.11 describes. The client
        // signs this one itself, so the types within its reach are not only the ones this server issued.
        var tokenType = token.Header.Type;
        if (!JwtTypes.IsPermitted(tokenType, JsonWebTokenTypes.ClientAuthentication))
        {
            LogOtherKindPresentedAsAssertion(clientInfo.ClientId, tokenType);
            return null;
        }

        if (!AudienceSatisfiesTheProfile(token, clientInfo))
        {
            return null;
        }

        if (!TimestampsSatisfyTheClientsOwnProfile(token, clientInfo))
        {
            return null;
        }

        if (!await ReserveTheAssertionAsync(token, clientInfo))
        {
            return null;
        }

        return clientInfo;
    }

    /// <summary>
    /// Claims the assertion's identifier so it cannot be presented a second time, answering whether
    /// the claim was granted.
    /// </summary>
    /// <remarks>
    /// Its own method because the reservation is irreversible, and a method ending in the spend
    /// cannot grow a check underneath it by accident: anything added to the caller lands before the
    /// call rather than after it.
    /// </remarks>
    /// <param name="token">The assertion whose identifier is being claimed.</param>
    /// <param name="clientInfo">The client the assertion authenticates.</param>
    private async Task<bool> ReserveTheAssertionAsync(JsonWebToken token, ClientInfo clientInfo)
    {
        // OIDC Core §9: the client-authentication assertion's jti is REQUIRED - "A unique
        // identifier for the token, which can be used to prevent reuse of the token". Reject an
        // assertion without it: single-use replay protection is impossible without a unique id,
        // and accepting it would leave the assertion replayable within its expiry window (the
        // replay cache below keys off jti).
        if (token is not { Payload.JwtId: { } jwtId })
        {
            LogMissingJti(clientInfo.ClientId);
            return false;
        }

        // RFC 7523 §3: the assertion MUST contain an 'exp' claim that limits the window during
        // which it can be used; the generic lifetime check treats a token with neither 'nbf' nor
        // 'exp' as valid, so this enforces the assertion-specific MUST and is also what bounds
        // the replay-cache entry's TTL.
        if (token is not { Payload.ExpiresAt: { } expiresAt })
        {
            LogMissingExpiration(clientInfo.ClientId);
            return false;
        }

        // Single atomic reserve-and-check: record the jti and treat "already present" as a replay.
        // One call avoids the read-then-write race a separate status check + mark step would leave
        // between two concurrent presenters of the same assertion.
        if (!await replayCache.TryReserveAsync(jwtId, expiresAt))
        {
            LogReplayDetected(jwtId, clientInfo.ClientId);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Validates the JWT assertion and returns the validation result along with client information.
    /// This method must be implemented by derived classes to provide their specific validation logic.
    /// </summary>
    /// <param name="jwt">The JWT assertion to validate.</param>
    /// <returns>
    /// A Result containing either a ValidJsonWebToken on success, or a JwtValidationError on failure.
    /// </returns>
    protected abstract Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateJwtAsync(string jwt);
}
