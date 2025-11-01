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

using System.Text;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

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
/// <param name="tokenRegistry">Registry for managing the status of JWTs, such as marking them as used or invalid.</param>
public class ClientSecretJwtAuthenticator(
    ILogger<ClientSecretJwtAuthenticator> logger,
    IJsonWebTokenValidator tokenValidator,
    IClientInfoProvider clientInfoProvider,
    IRequestInfoProvider requestInfoProvider,
    TimeProvider clock,
    ITokenRegistry tokenRegistry) : JwtAssertionAuthenticatorBase(logger, tokenRegistry)
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
    /// A tuple containing the validation result and the associated client information if validation is successful.
    /// </returns>
    protected override async Task<(JwtValidationResult result, ClientInfo? clientInfo)> ValidateJwtAsync(string jwt)
    {
        var context = new ValidationContext();

        var result = await tokenValidator.ValidateAsync(
            jwt,
            new ValidationParameters
            {
                Options = ValidationOptions.Default,
                ValidateAudience = ValidateAudience,
                ValidateIssuer = issuer => ValidateIssuer(issuer, context),
                ResolveIssuerSigningKeys = issuer => ResolveIssuerSigningKeys(issuer, context),
            });

        return (result, context.ClientInfo);
    }

    /// <summary>
    /// Context object used to pass state between validation methods during JWT validation process.
    /// </summary>
    private sealed class ValidationContext
    {
        /// <summary>
        /// Gets or sets the client information resolved during the validation process.
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
        var result = audiences.Contains(requestUri);
        if (!result)
        {
            logger.LogWarning(
                "Audience validation failed, token audiences: {@Audiences}, actual requestUri: {RequestUri}",
                audiences, requestUri);
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
            if (!string.Equals(issuer, context.ClientInfo.ClientId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Trying to validate issuer {issuer}, but already has info about client {context.ClientInfo.ClientId}");
            }

            return true;
        }

        context.ClientInfo = await clientInfoProvider.TryFindClientAsync(issuer).WithLicenseCheck();
        return context.ClientInfo != null;
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
            logger.LogWarning("No client secrets configured for client {ClientId}", client.ClientId);
            yield break;
        }

        var utcNow = clock.GetUtcNow();
        foreach (var clientSecret in client.ClientSecrets)
        {
            if (clientSecret.ExpiresAt.HasValue && clientSecret.ExpiresAt.Value < utcNow)
                continue;

            if (!clientSecret.Value.HasValue())
            {
                logger.LogWarning(
                    "Client secret for {ClientId} does not have a raw value, which is required for client_secret_jwt",
                    client.ClientId);
                continue;
            }

            // Provide keys for all supported HMAC algorithms
            // The JWT validator will use the one matching the JWT's alg header
            var secretBytes = Encoding.UTF8.GetBytes(clientSecret.Value);
            yield return CreateSymmetricKey(SecurityAlgorithms.HmacSha512, secretBytes);
            yield return CreateSymmetricKey(SecurityAlgorithms.HmacSha384, secretBytes);
            yield return CreateSymmetricKey(SecurityAlgorithms.HmacSha256, secretBytes);
        }
    }

    /// <summary>
    /// Creates a symmetric JSON Web Key for HMAC signature validation.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm identifier (e.g., HS256, HS384, HS512).</param>
    /// <param name="secret"></param>
    /// <returns>A JSON Web Key configured for the specified HMAC algorithm.</returns>
    private static JsonWebKey CreateSymmetricKey(string algorithm, byte[] secret) => new()
    {
        KeyType = JsonWebKeyTypes.Octet,
        Algorithm = algorithm,
        SymmetricKey = secret,
    };
}
