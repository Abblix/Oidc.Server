// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using JsonWebKey = Abblix.Jwt.JsonWebKey;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates client requests using the client_secret_jwt authentication method.
/// This method is used in scenarios where the client signs a JWT with its secret as a means of authentication.
/// </summary>
/// <param name="logger">Logger for recording the authentication process and any issues encountered.</param>
/// <param name="tokenValidator">Validator for JSON Web Tokens.</param>
/// <param name="clientInfoProvider">Provider for retrieving client information.</param>
/// <param name="requestInfoProvider">Provider for retrieving request information.</param>
/// <param name="clock">Time provider for checking secret expiration.</param>
/// <param name="replayCache">Replay cache that records assertion jti values and atomically rejects reuse.</param>
/// <param name="issuerProvider">Supplies the issuer identifier a profile-governed assertion must name.</param>
/// <param name="options">Supplies the server-wide default security profile.</param>
public partial class ClientSecretJwtAuthenticator(
    ILogger<ClientSecretJwtAuthenticator> logger,
    IJsonWebTokenValidator tokenValidator,
    IClientInfoProvider clientInfoProvider,
    IRequestInfoProvider requestInfoProvider,
    TimeProvider clock,
    IReplayCache replayCache,
    IIssuerProvider issuerProvider,
    IOptions<OidcOptions> options)
    : JwtAssertionAuthenticatorBase(logger, replayCache, issuerProvider, options)
{
    /// <summary>
    /// Specifies the client authentication method this authenticator supports, which is 'client_secret_jwt'.
    /// This indicates that the authenticator handles client authentication using JSON Web Tokens (JWT) for
    /// the client secret, as defined in the OpenID Connect specification. It involves using JWTs as
    /// client credentials for authentication, where the JWT assertion is signed by the client's secret key.
    /// </summary>
    public override IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.ClientSecretJwt; }
    }

    /// <summary>
    /// Validates the JWT assertion using HMAC signature with the client secret.
    /// </summary>
    /// <param name="jwt">The JWT assertion to validate.</param>
    /// <returns>
    /// A Result containing either a ValidJsonWebToken on success, or a JwtValidationError on failure.
    /// </returns>
    protected override async Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateJwtAsync(string jwt)
    {
        var context = new ValidationContext();

        var result = await tokenValidator.ValidateAsync(
            jwt,
            new ValidationParameters
            {
                // A client assertion must carry its own expiry: RFC 7521 Section 5.2 requires an
                // "Expires At entity that limits the time window during which the assertion can be
                // used", and RFC 7523 Section 3 item 4 states it as a MUST on the exp claim.
                Options = ValidationOptions.Default | ValidationOptions.RequireExpirationTime,
                ValidateAudience = ValidateAudience,
                ValidateIssuer = issuer => ValidateIssuer(issuer, context),
                ResolveIssuerSigningKeys = issuer => ResolveIssuerSigningKeys(issuer, context),
            });

        return result.MapSuccess(token => new ValidJsonWebToken(token, context.ClientInfo.NotNull(nameof(context.ClientInfo))));
    }

    /// <summary>
    /// Context object used to pass state between validation methods during JWT validation process.
    /// </summary>
    private sealed class ValidationContext
    {
        /// <summary>
        /// The client information resolved during the validation process.
        /// </summary>
        public ClientInfo? ClientInfo { get; set; }
    }

    /// <summary>
    /// Validates that the JWT's audience claim matches the current request URI.
    /// </summary>
    /// <param name="audiences">The audiences from the JWT to validate.</param>
    /// <returns>True if the audience is valid; otherwise, false.</returns>
    private Task<bool> ValidateAudience(IEnumerable<string> audiences)
    {
        var requestUri = requestInfoProvider.RequestUri;
        var materialized = audiences.Materialize();
        var result = materialized.Contains(requestUri);
        if (!result)
        {
            LogAudienceValidationFailed(materialized, requestUri);
        }

        return Task.FromResult(result);
    }

    /// <summary>
    /// Validates the JWT issuer and retrieves the associated client information.
    /// </summary>
    /// <param name="issuer">The issuer claim from the JWT.</param>
    /// <param name="context">The validation context to store resolved client information.</param>
    /// <returns>True if the issuer is valid and client was found; otherwise, false.</returns>
    private async Task<bool> ValidateIssuer(string issuer, ValidationContext context)
    {
        if (context.ClientInfo != null)
        {
            if (issuer != context.ClientInfo.ClientId)
            {
                throw new InvalidOperationException(
                    $"Trying to validate issuer {issuer}, but already has info about client {context.ClientInfo.ClientId}");
            }

            return true;
        }

        switch (await clientInfoProvider.TryFindClientAsync(issuer).WithLicenseCheck())
        {
            case { } clientInfo when clientInfo.TokenEndpointAuthMethod != ClientAuthenticationMethods.ClientSecretJwt:
                LogWrongAuthMethod(issuer);
                return false;

            case { } clientInfo:
                context.ClientInfo = clientInfo;
                return true;

            default:
                return false;
        }
    }

    /// <summary>
    /// Resolves the symmetric signing keys for validating the JWT signature.
    /// Creates HMAC keys from the client's secret for HS256, HS384, and HS512 algorithms.
    /// </summary>
    /// <param name="issuer">The issuer claim from the JWT.</param>
    /// <param name="context">The validation context containing client information.</param>
    /// <returns>An async enumerable of JSON Web Keys created from the client secrets.</returns>
    private async IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeys(string issuer, ValidationContext context)
    {
        if (!await ValidateIssuer(issuer, context))
            yield break;

        var client = context.ClientInfo.NotNull(nameof(context.ClientInfo));
        if (client.ClientSecrets is not { Length: > 0 })
        {
            LogNoSecretsConfigured(client.ClientId);
            yield break;
        }

        var utcNow = clock.GetUtcNow();
        foreach (var clientSecret in client.ClientSecrets)
        {
            if (clientSecret.ExpiresAt.HasValue && clientSecret.ExpiresAt.Value < utcNow)
                continue;

            if (!clientSecret.Value.HasValue())
            {
                LogSecretWithoutRawValue(client.ClientId);
                continue;
            }

            // Provide keys for all supported HMAC algorithms
            // The JWT validator will use the one matching the JWT's alg header
            var secretBytes = Encoding.UTF8.GetBytes(clientSecret.Value);
            yield return CreateSymmetricKey(SigningAlgorithms.HS512, secretBytes);
            yield return CreateSymmetricKey(SigningAlgorithms.HS384, secretBytes);
            yield return CreateSymmetricKey(SigningAlgorithms.HS256, secretBytes);
        }
    }

    /// <summary>
    /// Creates a symmetric JSON Web Key for HMAC signature validation.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm identifier (e.g., HS256, HS384, HS512).</param>
    /// <param name="secret">UTF-8 bytes of the client secret used as the HMAC key.</param>
    /// <returns>A JSON Web Key configured for the specified HMAC algorithm.</returns>
    private static OctetJsonWebKey CreateSymmetricKey(string algorithm, byte[] secret)
        => new() { Algorithm = algorithm, KeyValue = secret };
}
