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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

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
/// only valid and authorized clients can interact with the authentication service.
/// </remarks>
/// <param name="logger">The logger used for recording validation activities and outcomes.</param>
/// <param name="requestInfoProvider">Provides information about the current request, including the request URI.</param>
/// <param name="tokenValidator">The service used to perform core JWT validation.</param>
/// <param name="clientInfoProvider">Provides access to client information for validation purposes.</param>
/// <param name="clientJwksProvider">Provides access to the client's JSON Web Keys (JWKs) for verifying signatures.</param>
/// <param name="issuerProvider">Provides the authorization server's issuer identifier for audience validation.</param>
public class ClientJwtValidator(
    ILogger<ClientJwtValidator> logger,
    IRequestInfoProvider requestInfoProvider,
    IJsonWebTokenValidator tokenValidator,
    IClientInfoProvider clientInfoProvider,
    IClientKeysProvider clientJwksProvider,
    IIssuerProvider issuerProvider) : IClientJwtValidator
{
    /// <summary>
    /// Validates the JWT issued by a client, ensuring that it meets the expected criteria for issuer, audience,
    /// and cryptographic signatures. This method is used in scenarios such as private JWT client authentication
    /// and request object validation.
    /// </summary>
    /// <param name="jwt">The JWT to validate.</param>
    /// <param name="options">Options to customize the validation process.</param>
    /// <returns>
    /// A task that returns a Result containing either a ValidJsonWebToken on success,
    /// or a JwtValidationError on failure.
    /// </returns>
    public async Task<Result<ValidJsonWebToken, JwtValidationError>> ValidateAsync(
        string jwt,
        ValidationOptions options = ValidationOptions.Default)
    {
        var context = new ValidationContext(clientInfoProvider, clientJwksProvider);

        var result = await tokenValidator.ValidateAsync(
            jwt,
            new ValidationParameters
            {
                Options = options,
                ValidateAudience = ValidateAudience,
                ValidateIssuer = context.ValidateIssuer,
                ResolveIssuerSigningKeys = context.ResolveIssuerSigningKeys,
            });

        if (result.TryGetFailure(out var error))
        {
            logger.LogWarning(
                "Client JWT validation failed. Error: {ErrorType}, Description: {Description}",
                error.GetType().Name,
                error.ToString());
            return error;
        }

        var validatedToken = result.GetSuccess();

        var clientIdFromJwt = validatedToken.Payload.ClientId;
        if (clientIdFromJwt != null)
        {
            if (context.ClientInfo == null)
            {
                // No client found by issuer, try client_id claim
                context.ClientInfo = await clientInfoProvider.TryFindClientAsync(clientIdFromJwt).WithLicenseCheck();
            }
            else if (context.ClientInfo.ClientId != clientIdFromJwt)
            {
                // Both issuer and client_id present but don't match
                logger.LogWarning(
                    "Client ID mismatch: issuer resolves to {IssuerClientId}, but client_id claim is {ClaimClientId}",
                    context.ClientInfo.ClientId,
                    clientIdFromJwt);

                return new JwtValidationError(
                    JwtError.InvalidToken,
                    $"Client ID mismatch: issuer resolves to '{context.ClientInfo.ClientId}', but client_id claim is '{clientIdFromJwt}'");
            }
        }

        if (context.ClientInfo == null)
        {
            logger.LogWarning("Unable to determine client from JWT. No matching client found by issuer or client_id claim.");
            return new JwtValidationError(JwtError.InvalidToken, "Unable to determine client from JWT");
        }

        logger.LogInformation("Client JWT validation succeeded for client: {ClientId}", context.ClientInfo.ClientId);
        return new ValidJsonWebToken(validatedToken, context.ClientInfo);
    }

    /// <summary>
    /// Validates the audience by checking if it matches either the request URI (token endpoint)
    /// or the authorization server's issuer identifier.
    /// Per RFC 7523 Section 3 and OpenID Connect Core 1.0 Section 9, both values are acceptable.
    /// </summary>
    /// <param name="audiences">The collection of audiences to validate against valid audience values.</param>
    /// <returns>A task that returns whether the audience is valid.</returns>
    private Task<bool> ValidateAudience(IEnumerable<string> audiences)
    {
        var requestUri = requestInfoProvider.RequestUri;
        var issuer = issuerProvider.GetIssuer();

        var result = audiences.Contains(requestUri) || audiences.Contains(issuer);
        if (!result)
        {
            logger.LogWarning(
                "Audience validation failed, token audiences: {@Audiences}, expected requestUri: {RequestUri} or issuer: {Issuer}",
                audiences, requestUri, issuer);
        }

        return Task.FromResult(result);
    }

    /// <summary>
    /// Encapsulates the validation context for a single JWT validation operation.
    /// Holds client information that gets populated during the validation process.
    /// </summary>
    private sealed class ValidationContext(
        IClientInfoProvider clientInfoProvider,
        IClientKeysProvider clientJwksProvider)
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
                // Attempt to find the client by issuer
                ClientInfo = await clientInfoProvider.TryFindClientAsync(issuer).WithLicenseCheck();
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
        /// <returns>
        /// An asynchronous stream of <see cref="JsonWebKey" /> objects representing the issuer's signing keys.
        /// </returns>
        public async IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeys(string issuer)
        {
            // If issuer is not present, return empty sequence - client will be identified by client_id claim
            if (string.IsNullOrEmpty(issuer))
                yield break;

            if (!await ValidateIssuer(issuer))
                yield break;

            var clientInfo = ClientInfo.NotNull(nameof(ClientInfo));
            await foreach (var key in clientJwksProvider.GetSigningKeys(clientInfo))
                yield return key;
        }
    }
}
