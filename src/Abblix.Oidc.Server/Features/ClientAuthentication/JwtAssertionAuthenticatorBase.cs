// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Base class for JWT assertion-based client authenticators, providing common validation logic
/// for both private_key_jwt and client_secret_jwt authentication methods.
/// </summary>
/// <param name="logger">logger for recording the authentication process and any issues encountered.</param>
/// <param name="replayCache">Replay cache that records assertion jti values and atomically rejects reuse.</param>
/// <param name="timeProvider">Judges the assertion's timestamps against the client's own profile.</param>
/// <param name="serviceProvider">Resolves, per request, where the transport serves the token and backchannel
/// authentication endpoints, for a client allowed such a URL as its assertion's audience.</param>
/// <param name="options">Where the longest lifetime an assertion may have is read from, each time.</param>
public abstract partial class JwtAssertionAuthenticatorBase(
    ILogger logger,
    IReplayCache replayCache,
    TimeProvider timeProvider,
    IServiceProvider serviceProvider,
    IOptionsMonitor<OidcOptions> options) : IClientAuthenticator
{
    private readonly ClientAssertionReplay _replay = new(replayCache, options, timeProvider);
    private readonly ClientAssertionAudience _audience = new(logger, serviceProvider);

    /// <summary>
    /// The clock this class judges an assertion's timestamps by, exposed so a derived authenticator
    /// reads the same instant rather than capturing a second copy of the same dependency.
    /// </summary>
    protected TimeProvider Clock => timeProvider;

    /// <summary>
    /// The provider scoped dependencies are resolved from, exposed so a derived authenticator uses the same one
    /// rather than capturing a second copy of the same dependency.
    /// </summary>
    protected IServiceProvider Services => serviceProvider;

    /// <summary>
    /// The checks a validated assertion must pass before its timestamps are read.
    /// </summary>
    /// <remarks>
    /// Chain of Responsibility: each link may refuse the assertion and logs why; All stops at the first
    /// refusal, so the links run in the order listed and none of them spends anything. Held once for every
    /// authentication rather than built per request, which is why each link takes its subject as arguments.
    /// </remarks>
    private static readonly Func<JwtAssertionAuthenticatorBase, TenantDefinition, JsonWebToken, ClientInfo, bool>[]
        AssertionLinks =
        [
            static (self, _, _, client) => self.AuthMethodIsSupported(client),
            static (self, _, token, client) => self.SigningAlgorithmMatchesRegistration(token, client),
            static (self, _, token, _) => self.IssuerMatchesSubject(token),
            static (self, _, token, client) => self.TypeIsClientAuthentication(token, client),
            static (self, tenant, token, client) => self._audience.IsAccepted(tenant, token, client),
        ];

    /// <summary>
    /// The checks a derived authenticator hands the JWT validator: the defaults, an expiry the assertion must
    /// carry, and the audience left out, since <see cref="ClientAssertionAudience"/> alone judges it.
    /// </summary>
    /// <remarks>
    /// RFC 7521 Section 5.2 requires an "Expires At entity that limits the time window during which the
    /// assertion can be used", which RFC 7523 Section 3 item 4 spells as a MUST on exp. The audience stays
    /// required, so an assertion without one is still refused by the validator.
    /// </remarks>
    protected static ValidationOptions AssertionValidationOptions { get; } =
        (ValidationOptions.Default & ~ValidationOptions.ValidateAudience) | ValidationOptions.RequireExpirationTime;

    /// <summary>
    /// Specifies the client authentication methods supported by this authenticator.
    /// </summary>
    public abstract IEnumerable<string> ClientAuthenticationMethodsSupported { get; }

    /// <summary>
    /// The control bundle the tenant's default profile mandates, for a derived authenticator
    /// building its own validation parameters. Pass the tenant <see cref="ValidateJwtAsync"/> was
    /// handed: <see cref="TryAuthenticateClientAsync"/> judges the timestamps and the audience against
    /// that same tenant, and only that argument keeps the two in step.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    protected static SecurityProfileRequirements DefaultProfileRequirementsOf(TenantDefinition tenant)
        => SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile);

    /// <summary>
    /// Answers whether the assertion's timestamps sit inside the window the profile governing THIS
    /// CLIENT allows, which the validator could not ask: the client is identified from the assertion
    /// it is validating, so its profile is not known until the validation has finished.
    /// </summary>
    /// <remarks>
    /// The first pass ran under the window of the tenant's default profile, which is the widest any
    /// client can be given - the tenant's profile is a floor and a client may only tighten it. So
    /// this narrows and never widens.
    ///
    /// Placed before the identifier is reserved, because this path never gives a reservation back:
    /// a refusal after it would burn the assertion's own identifier on a request this check was
    /// going to reject.
    /// </remarks>
    /// <param name="tenant">The tenant whose default profile the client's own profile tightens.</param>
    /// <param name="timestamps">The assertion's timestamps, already read.</param>
    /// <param name="clientInfo">The client the assertion authenticates.</param>
    private bool TimestampsSatisfyTheClientsOwnProfile(
        TenantDefinition tenant, AssertionTimestamps timestamps, ClientInfo clientInfo)
    {
        var refusal = SecurityProfileRequirements
            .For(clientInfo, tenant.DefaultSecurityProfile)
            .ClockSkewOrDefault()
            .WhyRefused(
                timeProvider.GetUtcNow(),
                timestamps.NotBefore,
                timestamps.ExpiresAt,
                timestamps.IssuedAt);

        if (refusal is null)
            return true;

        LogTimestampsOutsideTheClientsProfile(clientInfo.ClientId, refusal);
        return false;
    }

    /// <summary>
    /// Attempts to authenticate a client using JWT assertion by validating the JWT provided in the client request.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at; the client is looked up there alone.</param>
    /// <param name="request">The client request containing the JWT to authenticate.</param>
    /// <param name="clients">The clients of the request being served, where the client is looked up.</param>
    /// <returns>The authenticated <see cref="ClientInfo"/>, or why it is not one: no assertion presented, or one
    /// presented and refused.</returns>
    public async Task<Result<ClientInfo, OidcError>> TryAuthenticateClientAsync(
        TenantDefinition tenant,
        ClientRequest request,
        IClientInfoProvider clients)
    {
        if (!IsPresented(request))
            return ClientAuthenticationFailures.NoCredential;

        if (!TryGetJwtBearerAssertion(request, out var assertion))
        {
            return ClientAuthenticationFailures.InvalidCredential;
        }

        var validationResult = await ValidateJwtAsync(tenant, clients, assertion);
        if (!validationResult.TryGetSuccess(out var validJwt))
        {
            var error = validationResult.GetFailure();
            LogJwtValidationError(Sanitized.Value(error));
            return ClientAuthenticationFailures.InvalidCredential;
        }

        var token = validJwt.Token;
        var clientInfo = validJwt.Client;

        if (!AssertionLinks.All(link => link(this, tenant, token, clientInfo)))
        {
            return ClientAuthenticationFailures.InvalidCredential;
        }

        // Refused before the identifier is reserved below, so a request naming another client spends nothing
        if (request.NamesAnotherClientThan(clientInfo.ClientId))
        {
            LogClientIdentifiersMismatch(clientInfo.ClientId, Sanitized.Value(request.ClientId));
            return ClientAuthenticationFailures.InvalidCredential;
        }

        // Read once for both consumers below, and refused rather than thrown where the payload
        // cannot read them: the validator an override chose may not have looked at these claims,
        // and a malformed date is the assertion's fault, not a fault in this server.
        if (!token.Payload.TryReadTimestamps(out var notBefore, out var expiresAt, out var issuedAt, out var whyUnreadable))
        {
            LogTimestampUnreadable(clientInfo.ClientId, whyUnreadable);
            return ClientAuthenticationFailures.InvalidCredential;
        }

        var timestamps = new AssertionTimestamps(notBefore, expiresAt, issuedAt);

        if (!TimestampsSatisfyTheClientsOwnProfile(tenant, timestamps, clientInfo))
        {
            return ClientAuthenticationFailures.InvalidCredential;
        }

        if (!await ReserveTheAssertionAsync(tenant, token, timestamps, clientInfo))
        {
            return ClientAuthenticationFailures.InvalidCredential;
        }

        return clientInfo;
    }

    /// <inheritdoc />
    public Task<IEnumerable<string>> FindPresentedCredentialsAsync(
        TenantDefinition tenant,
        ClientRequest request,
        IClientInfoProvider clients)
        => Task.FromResult<IEnumerable<string>>(IsPresented(request) ? [nameof(ClientRequest.ClientAssertion)] : []);

    /// <summary>
    /// The assertion is the credential; its type only says how to read it.
    /// </summary>
    private static bool IsPresented(ClientRequest request) => request.ClientAssertion.HasValue();

    /// <summary>
    /// Finds the JWT bearer assertion the request carries, logging a request that names another assertion type
    /// or names this one without a value.
    /// </summary>
    /// <param name="request">The client request.</param>
    /// <param name="assertion">The assertion when present.</param>
    private bool TryGetJwtBearerAssertion(ClientRequest request, [NotNullWhen(true)] out string? assertion)
    {
        assertion = null;
        if (request.ClientAssertionType is null)
        {
            return false;
        }

        if (request.ClientAssertionType != ClientAssertionTypes.JwtBearer)
        {
            LogWrongAssertionType();
            return false;
        }

        if (!request.ClientAssertion.HasValue())
        {
            LogMissingAssertion();
            return false;
        }

        assertion = request.ClientAssertion;
        return true;
    }

    /// <summary>
    /// Answers whether the client is registered for an authentication method this authenticator serves.
    /// </summary>
    private bool AuthMethodIsSupported(ClientInfo clientInfo)
    {
        var tokenEndpointAuthMethod = clientInfo.TokenEndpointAuthMethod;
        if (ClientAuthenticationMethodsSupported.Contains(
                tokenEndpointAuthMethod.NotNull(nameof(tokenEndpointAuthMethod))))
        {
            return true;
        }

        LogAuthMethodNotAllowed(clientInfo.ClientId);
        return false;
    }

    /// <summary>
    /// Answers whether the assertion is signed with the algorithm the client registered, when it registered one.
    /// </summary>
    private bool SigningAlgorithmMatchesRegistration(JsonWebToken token, ClientInfo clientInfo)
    {
        // OIDC Core section 9 / RFC 7591: when the client registered token_endpoint_auth_signing_alg, the
        // assertion MUST use exactly that algorithm. The signature is already verified by here; this
        // pins the registered algorithm so a client cannot authenticate with a different (e.g. weaker)
        // algorithm its key happens to support.
        var requiredSigningAlgorithm = clientInfo.TokenEndpointAuthSigningAlgorithm;
        if (!requiredSigningAlgorithm.HasValue() ||
            string.Equals(token.Header.Algorithm, requiredSigningAlgorithm, StringComparison.Ordinal))
        {
            return true;
        }

        LogSigningAlgorithmNotAllowed(clientInfo.ClientId, token.Header.Algorithm, requiredSigningAlgorithm);
        return false;
    }

    /// <summary>
    /// Answers whether the assertion names the same client as its issuer and its subject.
    /// </summary>
    private bool IssuerMatchesSubject(JsonWebToken token)
    {
        string? subject;
        try
        {
            subject = token.Payload.Subject;
        }
        catch (InvalidOperationException ex)
        {
            LogSubjectExtractionFailed(ex, ex.Message);
            return false;
        }

        var issuer = token.Payload.Issuer;
        if (issuer != null && subject != null && issuer == subject)
        {
            return true;
        }

        LogIssuerSubjectMismatch(issuer, subject);
        return false;
    }

    /// <summary>
    /// Answers whether the assertion does not declare itself some other kind of token this server names.
    /// </summary>
    private bool TypeIsClientAuthentication(JsonWebToken token, ClientInfo clientInfo)
    {
        // An assertion authenticates the client; it is not a token this server issued. RFC 10070 section 4 says
        // client authentication JWTs "SHOULD be explicitly typed by using the "typ" header parameter value
        // "client-authentication+jwt" or another more specific explicit type value defined by a specification
        // profiling this specification", and calls it "NOT RECOMMENDED for servers to reject JWTs that do not have
        // explicit types", so the exact value cannot be demanded. What can be refused is a JWT declaring itself some
        // other type this class names, which is the replay RFC 8725 section 3.11 describes. The client signs this
        // one itself, so the types within its reach are not only the ones this server issued.
        var tokenType = token.Header.Type;
        if (JwtTypes.IsPermitted(tokenType, JsonWebTokenTypes.ClientAuthentication))
        {
            return true;
        }

        LogOtherKindPresentedAsAssertion(clientInfo.ClientId, tokenType);
        return false;
    }

    /// <summary>
    /// The three timestamps an assertion may carry, read once so that no later step meets the
    /// accessors again.
    /// </summary>
    private readonly record struct AssertionTimestamps(
        DateTimeOffset? NotBefore,
        DateTimeOffset? ExpiresAt,
        DateTimeOffset? IssuedAt);

    /// <summary>
    /// Claims the assertion's identifier so it cannot be presented a second time, answering whether
    /// the claim was granted.
    /// </summary>
    /// <remarks>
    /// Its own method because the reservation is irreversible, and a method ending in the spend is
    /// where a check added later is least likely to land underneath it: the natural place to add one
    /// in the caller is before the call.
    /// </remarks>
    /// <param name="tenant">The tenant whose default profile the client's clock skew is drawn from.</param>
    /// <param name="token">The assertion whose identifier is being claimed.</param>
    /// <param name="timestamps">The assertion's timestamps, already read; the expiry bounds the reservation.</param>
    /// <param name="clientInfo">The client the assertion authenticates.</param>
    private async Task<bool> ReserveTheAssertionAsync(
        TenantDefinition tenant, JsonWebToken token, AssertionTimestamps timestamps, ClientInfo clientInfo)
    {
        // OIDC Core section 9: the client-authentication assertion's jti is REQUIRED - "A unique
        // identifier for the token, which can be used to prevent reuse of the token". Reject an
        // assertion without it: single-use replay protection is impossible without a unique id,
        // and accepting it would leave the assertion replayable within its expiry window (the
        // replay cache below keys off jti).
        if (token is not { Payload.JwtId: { } jwtId })
        {
            LogMissingJti(clientInfo.ClientId);
            return false;
        }

        // RFC 7523 section 3: the assertion MUST contain an 'exp' claim that limits the window during
        // which it can be used; the generic lifetime check treats a token with neither 'nbf' nor
        // 'exp' as valid, so this enforces the assertion-specific MUST and is also what bounds
        // the replay-cache entry's TTL.
        if (timestamps.ExpiresAt is not { } expiry)
        {
            LogMissingExpiration(clientInfo.ClientId);
            return false;
        }

        // RFC 7523 section 3 item 4: "the authorization server may reject JWTs with an "exp" claim value that is
        // unreasonably far in the future", and the reservation below would otherwise be held for as long
        var forwardSkew = SecurityProfileRequirements
            .For(clientInfo, tenant.DefaultSecurityProfile)
            .ClockSkewOrDefault()
            .Future;
        if (_replay.WhyTooLong(expiry, timestamps.IssuedAt, forwardSkew) is { } tooLong)
        {
            LogLifetimeTooLong(clientInfo.ClientId, tooLong);
            return false;
        }

        if (!await _replay.TryReserveAsync(clientInfo.ClientId, jwtId, expiry))
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
    /// <param name="tenant">The tenant the request is served at; the client is looked up there alone.</param>
    /// <param name="clients">The clients of the request being served, where the client is looked up.</param>
    /// <param name="jwt">The JWT assertion to validate.</param>
    /// <returns>
    /// A Result containing either a ValidJsonWebToken on success, or a JwtValidationError on failure.
    /// </returns>
    protected abstract Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateJwtAsync(
        TenantDefinition tenant, IClientInfoProvider clients, string jwt);
}
