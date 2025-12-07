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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.ClientRequest.Parameters;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Base class for JWT assertion-based client authenticators, providing common validation logic
/// for both private_key_jwt and client_secret_jwt authentication methods.
/// </summary>
/// <param name="logger">logger for recording the authentication process and any issues encountered.</param>
/// <param name="tokenRegistry">Registry for managing the status of JWTs, such as marking them as used or invalid.</param>
public abstract class JwtAssertionAuthenticatorBase(
    ILogger logger,
    ITokenRegistry tokenRegistry) : IClientAuthenticator
{
    /// <summary>
    /// Specifies the client authentication methods supported by this authenticator.
    /// </summary>
    public abstract IEnumerable<string> ClientAuthenticationMethodsSupported { get; }

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
            logger.LogWarning($"{ClientAssertionType} is not '{ClientAssertionTypes.JwtBearer}'");
            return null;
        }

        if (!request.ClientAssertion.HasValue())
        {
            logger.LogWarning($"{ClientAssertionType} is '{ClientAssertionTypes.JwtBearer}', but {ClientAssertion} is empty");
            return null;
        }

        var validationResult = await ValidateJwtAsync(request.ClientAssertion);

        if (!validationResult.TryGetSuccess(out var validJwt))
        {
            var error = validationResult.GetFailure();
            logger.LogWarning("JWT validation error: {@Error}", error);
            return null;
        }

        var token = validJwt.Token;
        var clientInfo = validJwt.Client;

        var tokenEndpointAuthMethod = clientInfo.TokenEndpointAuthMethod;
        if (!ClientAuthenticationMethodsSupported.Contains(tokenEndpointAuthMethod.NotNull(nameof(tokenEndpointAuthMethod))))
        {
            logger.LogWarning("The authentication method is not allowed for the client {@ClientId}", clientInfo.ClientId);
            return null;
        }

        string? subject;
        try
        {
            subject = token.Payload.Subject;
        }
        catch (InvalidOperationException ex)
        {
            logger.LogWarning("The error while getting subject: {Message}", ex.Message);
            return null;
        }

        var issuer = token.Payload.Issuer;
        if (issuer == null || subject == null || issuer != subject)
        {
            logger.LogWarning("The error during authentication: iss is '{Issuer}', but sub is {Subject}", issuer, subject);
            return null;
        }

        if (token is { Payload: { JwtId: { } jwtId, ExpiresAt: { } expiresAt } })
        {
            await tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, expiresAt);
        }

        return clientInfo;
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
