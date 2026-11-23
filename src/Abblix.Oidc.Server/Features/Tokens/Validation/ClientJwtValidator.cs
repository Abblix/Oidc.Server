// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Validates JWTs issued by clients to the authentication service, supporting scenarios such as private JWT client
/// authentication and the validation of request objects. This class plays a crucial role in ensuring that
/// tokens received from clients are legitimate, properly signed, and authorized for use within
/// the authentication service.
/// </summary>
/// <remarks>
/// The class is used for validating tokens like client authentication JWTs and request objects in OpenID Connect
/// flows. It checks the authenticity of the JWT issuer, audience, and cryptographic signatures to ensure that
/// only valid and authorized clients can interact with the authentication service. A client authentication JWT
/// is validated without the audience check: <c>JwtAssertionAuthenticatorBase</c> judges its audience, which
/// RFC 10070 section 4 restricts to the issuer identifier alone.
/// </remarks>
/// <param name="logger">The logger used for recording validation activities and outcomes.</param>
/// <param name="requestInfoProvider">Names the address a token whose audience is refused arrived at; no audience is
/// taken from it.</param>
/// <param name="tokenValidator">The service used to perform core JWT validation.</param>
/// <param name="clientJwksProvider">Provides access to the client's JSON Web Keys (JWKs) for verifying signatures.</param>
/// <param name="serviceKeysProvider">Provides the server's own private keys used to decrypt request
/// objects that the client encrypted to the server (RFC 9101 section 6.1).</param>
/// <param name="timeProvider">Judges the token's timestamps against the client's own profile, once
/// the client is known.</param>
public partial class ClientJwtValidator(
    ILogger<ClientJwtValidator> logger,
    IRequestInfoProvider requestInfoProvider,
    ProfiledJwtValidator tokenValidator,
    IClientKeysProvider clientJwksProvider,
    IAuthServiceKeysProvider serviceKeysProvider,
    TimeProvider timeProvider) : IClientJwtValidator
{
    /// <summary>
    /// Validates the JWT issued by a client, ensuring that it meets the expected criteria for issuer, audience,
    /// and cryptographic signatures. This method is used in scenarios such as private JWT client authentication
    /// and request object validation.
    /// </summary>
    /// <param name="tenant">The tenant the token is for.</param>
    /// <param name="client">The client the request names outside the token, or null.</param>
    /// <param name="clients">The clients of the request being served, where a client the token names is looked
    /// up.</param>
    /// <param name="jwt">The JWT to validate.</param>
    /// <param name="tokenTypes">The token types the caller accepts.</param>
    /// <param name="signingAlgorithms">The signature algorithms the caller admits, within those the security
    /// profile admits, refused before any client is looked up; null where the caller narrows nothing.</param>
    /// <param name="options">Options to customize the validation process.</param>
    /// <returns>
    /// A task that returns a Result containing either a ValidJsonWebToken on success,
    /// or a JwtValidationError on failure.
    /// </returns>
    public async Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateAsync(
        TenantDefinition tenant,
        ClientInfo? client,
        IClientInfoProvider clients,
        string jwt,
        TokenTypePolicy tokenTypes,
        IReadOnlySet<string>? signingAlgorithms,
        ValidationOptions options = ValidationOptions.Default)
    {
        var context = new ValidationContext(clients, clientJwksProvider, tenant, client);

        // The token is validated under the profile of the client the request names outside it, or what the
        // deployment demands of every client where it names none, the guard holding its signature and each JWE layer
        // to that profile; each layer is recorded so the profile of the client the token names can judge it too
        var deployment = SecurityProfileRequirements.For(tenant, client);
        var keyManagementAlgorithms = new List<string>();

        var result = await tokenValidator.ValidateAsync(
            deployment,
            jwt,
            new ValidationParameters
            {
                Options = options,
                TokenTypes = tokenTypes,
                AllowedSigningAlgorithms = signingAlgorithms,
                ValidateAudience = audiences => ValidateAudience(tenant, audiences),
                ValidateIssuer = context.ValidateIssuer,
                ResolveIssuerSigningKeys = issuer => context.ResolveIssuerSigningKeys(issuer),
                RefetchIssuerSigningKeys = issuer => context.ResolveIssuerSigningKeys(issuer, refetch: true),
                // RFC 9101 section 6.1: a request object may be JWE-encrypted to the server. Decrypt it with
                // the server's own private keys a client can encrypt to, the keys discovery derives its
                // request_object_encryption_alg_values_supported from; the inner JWS is then verified with the
                // client's key via ResolveIssuerSigningKeys. Harmless for plain JWS client assertions (the JWE
                // path only runs for an actual JWE token).
                ResolveTokenDecryptionKeys = _ => serviceKeysProvider.GetInboundEncryptionKeys(tenant, true),
                // The tolerance belongs to the profile this deployment is held to, ceiling
                // included.
                ClockSkew = deployment.ClockSkewOrDefault(),
                ValidateKeyManagementAlgorithm = algorithm =>
                {
                    keyManagementAlgorithms.Add(algorithm);
                    return true;
                },
            });

        if (result.TryGetFailure(out var error))
        {
            LogValidationFailed(error.GetType().Name, error.ToString());
            return error;
        }

        var validatedToken = result.GetSuccess();

        var determined = await DetermineClientAsync(tenant, clients, client, context, validatedToken);
        if (determined.TryGetFailure(out var undetermined))
            return undetermined;

        var tokenClient = determined.GetSuccess();

        var profile = SecurityProfileRequirements.For(tokenClient, tenant.DefaultSecurityProfile);

        if (profile.AlgorithmOutside(validatedToken, keyManagementAlgorithms) is { } algorithm)
        {
            LogAlgorithmOutsideTheClientsProfile(tokenClient.ClientId, Sanitized.Value(algorithm));
            return new JwtValidationError(
                JwtError.InvalidToken, "The token uses an algorithm the client's security profile does not admit");
        }

        // The pass above ran under the window of the client the request named outside the token, or the
        // deployment's where it named none, because the client the token itself names is not known until
        // that pass has finished. That client may be held to a tighter one, and this is the first line
        // where it can be asked. It only narrows: what the pass applied is a floor, so no client's window
        // is wider than the one already applied.
        //
        // The same flag the pass above reads, because the caller's options are handed to it
        // unchanged where the validation parameters are built. Not symmetry for its own sake: a
        // caller that opted out of time handling must not meet the timestamp accessors either,
        // since they throw on a value outside the range DateTimeOffset can hold.
        if (options.HasFlag(ValidationOptions.ValidateLifetime))
        {
            // Read through the same door the first pass uses rather than the accessors: the first
            // pass belongs to whichever validator the host registered, which may not have read these
            // claims, and an unreadable one is a refusal here as it is there.
            if (!validatedToken.Payload.TryReadTimestamps(
                    out var notBefore, out var expiresAt, out var issuedAt, out var whyUnreadable))
            {
                LogTimestampUnreadable(tokenClient.ClientId, whyUnreadable);
                return new JwtValidationError(JwtError.InvalidToken, whyUnreadable);
            }

            var refusal = profile
                .ClockSkewOrDefault()
                .WhyRefused(timeProvider.GetUtcNow(), notBefore, expiresAt, issuedAt);

            if (refusal != null)
            {
                LogTimestampsOutsideTheClientsProfile(tokenClient.ClientId, refusal);
                return new JwtValidationError(JwtError.InvalidToken, refusal);
            }
        }

        LogValidationSucceeded(tokenClient.ClientId);
        return new ValidJsonWebToken(validatedToken, tokenClient);
    }

    /// <summary>
    /// Settles the client the token speaks for on <paramref name="context"/>: the one its issuer resolved to, else the
    /// one its client_id claim names, else, for an unsecured token naming neither, the one the request names.
    /// </summary>
    /// <returns>The client, or the refusal when the token names two clients or none can be determined.</returns>
    private async Task<Result<ClientInfo, JwtValidationError>> DetermineClientAsync(
        TenantDefinition tenant,
        IClientInfoProvider clients,
        ClientInfo? client,
        ValidationContext context,
        JsonWebToken validatedToken)
    {
        var clientIdFromJwt = validatedToken.Payload.ClientId;
        if (clientIdFromJwt != null)
        {
            if (context.ClientInfo == null)
            {
                // No client found by issuer, try client_id claim
                context.ClientInfo = await FindClientAsync(tenant, clients, client, clientIdFromJwt);
            }
            else if (context.ClientInfo.ClientId != clientIdFromJwt)
            {
                // Both issuer and client_id present but don't match
                LogClientIdMismatch(context.ClientInfo.ClientId, clientIdFromJwt);

                return new JwtValidationError(
                    JwtError.InvalidToken,
                    $"Client ID mismatch: issuer resolves to '{context.ClientInfo.ClientId}', but client_id claim is '{clientIdFromJwt}'");
            }
        }

        // OpenID Connect Core 1.0 section 6.1 asks a request object for iss only "If signed", and has the client_id
        // outside it "match those in the Request Object, if present", so an unsecured token naming neither speaks for
        // the client the request names. A signed one must name its own, since its key is looked up by it
        if (context.ClientInfo == null && clientIdFromJwt == null && UnsecuredToken.Is(validatedToken))
            context.ClientInfo = client;

        if (context.ClientInfo == null)
        {
            LogClientNotDetermined();
            return new JwtValidationError(JwtError.InvalidToken, "Unable to determine client from JWT");
        }

        return context.ClientInfo;
    }

    /// <summary>
    /// Validates the audience of a JWT the client sent other than a client authentication assertion - a request
    /// object, a login hint token - by checking that it names the authorization server's issuer identifier, as
    /// written. The server's own client authenticators validate an assertion without this check and judge its
    /// audience in <c>JwtAssertionAuthenticatorBase</c>.
    /// </summary>
    /// <remarks>
    /// The refusal rests on RFC 7519 section 4.1.3: "If the principal processing the claim does not identify itself
    /// with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected". This server
    /// identifies itself by its issuer identifier alone, the value the specifications give a signed request object:
    /// RFC 9101 section 4, "If signed, ... The value of "aud" should be the value of the authorization server (AS)
    /// "issuer"", OpenID Connect Core 1.0 section 6.1, "If signed, ... The aud value SHOULD be or include the OP's
    /// Issuer Identifier URL", RFC 9126 section 3 applying the JAR rules to a pushed one, and CIBA Core 1.0 section
    /// 7.1.1, under which a signed authentication request's "Audience claim MUST contain the value of the Issuer
    /// Identifier for the OP". None names an endpoint URL. For a login_hint_token the issuer alone is this server's
    /// policy, since CIBA Core 1.0 section 7.1 leaves "The particular details and security requirements for the
    /// login_hint_token" to the deployment or profile. Nothing compared is taken from the request: a host serving one
    /// tenant answers on whatever host a request names, so an address built on it would match an object a client
    /// signed for another server reached by the same path. The request's address is only logged, so a refusal shows
    /// where the object arrived.
    /// </remarks>
    /// <param name="tenant">The tenant whose issuer identifier is the audience the token must name.</param>
    /// <param name="audiences">The collection of audiences to validate against valid audience values.</param>
    /// <returns>A task that returns whether the audience is valid.</returns>
    private Task<bool> ValidateAudience(TenantDefinition tenant, IEnumerable<string> audiences)
    {
        var materializedAudiences = audiences.Materialize();
        var result = tenant.IssuerIsNamedByAny(materializedAudiences);
        if (!result)
        {
            LogAudienceValidationFailed(
                Sanitized.Values(materializedAudiences),
                Sanitized.Value(requestInfoProvider.RequestUri.OriginalString),
                tenant.IssuerAsWritten());
        }

        return Task.FromResult(result);
    }

    /// <summary>
    /// The client <paramref name="clientId"/> names: the one the request names outside the token when it is that one,
    /// as it is already found, else the one the store holds, or null.
    /// </summary>
    private static async Task<ClientInfo?> FindClientAsync(
        TenantDefinition tenant, IClientInfoProvider clients, ClientInfo? named, string clientId)
    {
        if (named?.ClientId == clientId)
            return named;

        return (await clients.FindClientAsync(tenant, clientId)).TryGetSuccess(out var found) ? found : null;
    }

    /// <summary>
    /// Encapsulates the validation context for a single JWT validation operation.
    /// Holds client information that gets populated during the validation process.
    /// </summary>
    /// <param name="clients">Finds the client the token's issuer names.</param>
    /// <param name="clientJwksProvider">Reads the keys the client signs with.</param>
    /// <param name="tenant">The tenant the token is for.</param>
    /// <param name="named">The client the request names outside the token, already found, or null.</param>
    private sealed class ValidationContext(
        IClientInfoProvider clients,
        IClientKeysProvider clientJwksProvider,
        TenantDefinition tenant,
        ClientInfo? named)
    {
        /// <summary>
        /// Holds client information after the issuer has been successfully validated.
        /// </summary>
        public ClientInfo? ClientInfo { get; set; }

        /// <summary>
        /// Tracks whether client lookup has been performed to avoid duplicate lookups.
        /// </summary>
        private bool _clientLookupPerformed;

        /// <summary>
        /// Validates the issuer by attempting to match it with known client information. Ensures that the JWT issuer
        /// corresponds to an authorized client, and handles scenarios where client information is already known.
        /// If issuer is not present (null or empty), validation succeeds to allow client identification via client_id claim.
        /// </summary>
        /// <param name="issuer">The issuer value to validate.</param>
        /// <returns>
        /// A task that returns whether the issuer is valid
        /// and corresponds to an authorized client.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown if attempting to validate a different issuer than the one
        /// associated with the stored client information.
        /// </exception>
        public async Task<bool> ValidateIssuer(string issuer)
        {
            // If issuer is not present, accept it - client will be identified by client_id claim
            if (string.IsNullOrEmpty(issuer))
                return true;

            if (!_clientLookupPerformed)
            {
                // Attempt to find the client by issuer, unless it is the one the request already found
                if (named?.ClientId == issuer)
                    ClientInfo = named;
                else if ((await clients.FindClientAsync(tenant, issuer)).TryGetSuccess(out var client))
                    ClientInfo = client;

                _clientLookupPerformed = true;
            }

            return ClientInfo?.ClientId == issuer;
        }

        /// <summary>
        /// Asynchronously resolves the signing keys for a validated issuer's JWTs, allowing the authentication service
        /// to verify the JWT signature.
        /// If issuer is not present, returns empty sequence as client will be identified by client_id claim.
        /// </summary>
        /// <param name="issuer">The issuer URL whose signing keys are to be resolved.</param>
        /// <param name="refetch">Whether to read the client's published keys again past the copy held.</param>
        /// <returns>
        /// An asynchronous stream of <see cref="JsonWebKey" /> objects representing the issuer's signing keys.
        /// </returns>
        public async IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeys(string issuer, bool refetch = false)
        {
            // If issuer is not present, return empty sequence - client will be identified by client_id claim
            if (string.IsNullOrEmpty(issuer))
                yield break;

            if (!await ValidateIssuer(issuer))
                yield break;

            var clientInfo = ClientInfo.NotNull(nameof(ClientInfo));

            // FAPI 1.0 Part 2 section 8.9 "requires that jwks_uri endpoints shall be served over TLS". Held here, where
            // the keys are read, so no path verifies with keys fetched in the clear, whatever schemes the host lets
            // the fetcher use
            if (SecurityProfileConsistency.FindJwksUriViolations(
                    clientInfo.JwksUri,
                    SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile)).Count > 0)
            {
                yield break;
            }

            await foreach (var key in clientJwksProvider.GetSigningKeys(clientInfo, refetch))
                yield return key;
        }
    }
}
