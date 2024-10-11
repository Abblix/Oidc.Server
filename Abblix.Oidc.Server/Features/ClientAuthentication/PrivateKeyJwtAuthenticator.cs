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
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.ClientRequest.Parameters;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates clients using the Private Key JWT method, verifying the client's identity through a signed JWT
/// that the client provides. This method is suitable for clients that can securely store and use private keys.
/// </summary>
public class PrivateKeyJwtAuthenticator : IClientAuthenticator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyJwtAuthenticator"/> class.
    /// </summary>
    /// <param name="logger">Logger for recording the authentication process and any issues encountered.</param>
    /// <param name="tokenRegistry">Registry for managing the status of JWTs, such as marking them as used or invalid.
    /// </param>
    /// <param name="serviceProvider">Service provider used to resolve scoped dependencies.</param>
    public PrivateKeyJwtAuthenticator(
        ILogger<PrivateKeyJwtAuthenticator> logger,
        ITokenRegistry tokenRegistry,
        IServiceProvider serviceProvider)
    {
        _logger = logger;
        _tokenRegistry = tokenRegistry;
        _serviceProvider = serviceProvider;
    }

    private readonly ILogger _logger;
    private readonly ITokenRegistry _tokenRegistry;
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Indicates the client authentication method supported by this authenticator.
    /// This method uses private keys and JSON Web Tokens (JWT) for client authentication,
    /// allowing clients to assert their identity through the use of asymmetric key cryptography.
    /// It is designed for environments where the client can securely hold a private key.
    /// </summary>
    public IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.PrivateKeyJwt; }
    }

    /// <summary>
    /// Attempts to authenticate a client using the Private Key JWT method by validating the JWT provided in
    /// the client request.
    /// </summary>
    /// <param name="request">The client request containing the JWT to authenticate.</param>
    /// <returns>The authenticated <see cref="ClientInfo"/>, or null if authentication fails.</returns>
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        if (request.ClientAssertionType != ClientAssertionTypes.JwtBearer)
        {
            _logger.LogWarning(
                $"{ClientAssertionType} is not '{ClientAssertionTypes.JwtBearer}'");
            return null;
        }

        if (!request.ClientAssertion.HasValue())
        {
            _logger.LogWarning(
                $"{ClientAssertionType} is '{ClientAssertionTypes.JwtBearer}', but {ClientAssertion} is empty");
            return null;
        }

        JwtValidationResult? result;
        ClientInfo? clientInfo;
        using (var scope = _serviceProvider.CreateScope())
        {
            var tokenValidator = scope.ServiceProvider.GetRequiredService<IClientJwtValidator>();
            (result, clientInfo) = await tokenValidator.ValidateAsync(request.ClientAssertion);
        }

        JsonWebToken token;
        switch (result, clientInfo)
        {
            case (ValidJsonWebToken validToken, { TokenEndpointAuthMethod: ClientAuthenticationMethods.PrivateKeyJwt }):
                token = validToken.Token;
                break;

            case (ValidJsonWebToken, clientInfo: not null):
                _logger.LogWarning(
                    "The authentication method is not allowed for the client {@ClientId}",
                    clientInfo.ClientId);
                return null;

            case (ValidJsonWebToken, clientInfo: null):
                _logger.LogWarning("Something went wrong, token cannot be validated without client specified");
                return null;

            case (JwtValidationError error, _):
                _logger.LogWarning("Invalid PrivateKeyJwt: {@Error}", error);
                return null;

            default:
                throw new UnexpectedTypeException(nameof(result), result.GetType());
        }

        string? subject;
        try
        {
            subject = token.Payload.Subject;
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("Invalid PrivateKeyJwt: {Message}", ex.Message);
            return null;
        }

        var issuer = token.Payload.Issuer;
        if (issuer == null || subject == null || issuer != subject)
        {
            _logger.LogWarning(
                "Invalid PrivateKeyJwt: iss is \'{Issuer}\', but sub is {Subject}",
                issuer, subject);

            return null;
        }

        if (token is { Payload: { JwtId: { } jwtId, ExpiresAt: { } expiresAt } })
        {
            await _tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, expiresAt);
        }

        return clientInfo;
    }
}
