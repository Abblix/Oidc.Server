// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.ClientRequest.Parameters;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates client requests using the Private Key JWT authentication method.
/// This method is typically used in scenarios where clients can securely hold a private key and
/// authenticate by providing a JWT signed with that key.
/// </summary>
public class PrivateKeyJwtAuthenticator : IClientAuthenticator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyJwtAuthenticator"/> class.
    /// </summary>
    /// <param name="logger">Logger for logging authentication process information and warnings.</param>
    /// <param name="tokenValidator">Validator for JSON Web Tokens (JWT) used in client assertions.</param>
    /// <param name="clientInfoProvider">Provider for retrieving client information,
    /// essential for validating client identity.</param>
    /// <param name="requestInfoProvider">Provider for retrieving information about the current request,
    /// used in validating JWT claims like audience.</param>
    /// <param name="tokenRegistry">Registry for managing the status of tokens, such as marking them used.</param>
    /// <param name="clientJwksProvider">Provider for retrieving client JSON Web Key Sets (JWKS),
    /// necessary for validating JWT signatures.</param>
    public PrivateKeyJwtAuthenticator(
        ILogger<PrivateKeyJwtAuthenticator> logger,
        IJsonWebTokenValidator tokenValidator,
        IClientInfoProvider clientInfoProvider,
        IRequestInfoProvider requestInfoProvider,
        ITokenRegistry tokenRegistry,
        IClientKeysProvider clientJwksProvider)
    {
        _logger = logger;
        _tokenValidator = tokenValidator;
        _clientInfoProvider = clientInfoProvider;
        _requestInfoProvider = requestInfoProvider;
        _tokenRegistry = tokenRegistry;
        _clientJwksProvider = clientJwksProvider;
    }

    private readonly ILogger _logger;
    private readonly IJsonWebTokenValidator _tokenValidator;
    private readonly IClientInfoProvider _clientInfoProvider;
    private readonly IRequestInfoProvider _requestInfoProvider;
    private readonly ITokenRegistry _tokenRegistry;
    private readonly IClientKeysProvider _clientJwksProvider;

    /// <summary>
    /// Indicates the client authentication method supported by this authenticator.
    /// This method utilizes private keys and JSON Web Tokens (JWT) for client authentication,
    /// allowing clients to assert their identity through the use of asymmetric key cryptography.
    /// It is designed for environments where the client can securely hold a private key.
    /// </summary>
    public IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.PrivateKeyJwt; }
    }

    /// <summary>
    /// Asynchronously tries to authenticate a client request using the Private Key JWT method.
    /// Validates the JWT and checks if the client is authorized to use this authentication method.
    /// </summary>
    /// <param name="request">The client request to authenticate.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield the
    /// authenticated <see cref="ClientInfo"/>, or null if the authentication is unsuccessful.
    /// </returns>
    public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        if (request.ClientAssertionType != ClientAssertionTypes.JwtBearer)
            return null;

        if (!request.ClientAssertion.HasValue())
        {
            _logger.LogWarning($"{ClientAssertionType} is '{ClientAssertionTypes.JwtBearer}', but {ClientAssertion} is empty");
            return null;
        }

        var issuerValidator = new IssuerValidator(_clientInfoProvider, _clientJwksProvider);

        var result = await _tokenValidator.ValidateAsync(
            request.ClientAssertion,
            new ValidationParameters
            {
                ValidateAudience = ValidateAudience,
                ValidateIssuer = issuerValidator.ValidateIssuer,
                ResolveIssuerSigningKeys = issuerValidator.ResolveIssuerSigningKeys,
            });

        JsonWebToken token;
        switch (result)
        {
            case ValidJsonWebToken validToken:
                token = validToken.Token;
                break;

            case JwtValidationError error:
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

        if (token is { Payload: { JwtId: { } jwtId, ExpiresAt: {} expiresAt } })
        {
            await _tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, expiresAt);
        }

        return issuerValidator.ClientInfo;
    }

    private Task<bool> ValidateAudience(IEnumerable<string> audiences)
    {
        var requestUri = _requestInfoProvider.RequestUri;
        var result = audiences.Contains(requestUri);
        if (!result)
        {
            _logger.LogWarning(
                "Audience validation failed, token audiences: {@Audiences}, actual requestUri: {RequestUri}",
                audiences, requestUri);
        }

        return Task.FromResult(result);
    }

    /// <summary>
    /// Validates issuers and resolves their signing keys to ensure secure token validation and authentication processes.
    /// </summary>
    /// <remarks>
    /// This class plays a critical role in the security infrastructure by validating token issuers against known client
    /// information and resolving the issuer's signing keys for JWT validation. It supports the secure and reliable
    /// verification of JWTs, which are central to authentication and authorization mechanisms.
    /// </remarks>
    private class IssuerValidator
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerValidator"/> class.
        /// </summary>
        /// <param name="clientInfoProvider">Provides access to client information.</param>
        /// <param name="clientJwksProvider">Provides access to the client's JSON Web Keys (JWKs).</param>
        public IssuerValidator(IClientInfoProvider clientInfoProvider, IClientKeysProvider clientJwksProvider)
        {
            _clientInfoProvider = clientInfoProvider;
            _clientJwksProvider = clientJwksProvider;
        }

        private readonly IClientInfoProvider _clientInfoProvider;
        private readonly IClientKeysProvider _clientJwksProvider;

        /// <summary>
        /// The client information if the issuer has been successfully validated.
        /// </summary>
        public ClientInfo? ClientInfo { get; private set; }

        /// <summary>
        /// Validates the issuer by attempting to match it with known client information. If the issuer has already been
        /// validated and stored in <see cref="ClientInfo"/>, the method checks if the provided issuer matches
        /// the stored client ID. Throws an exception if a mismatch is detected, ensuring that
        /// the validator is not misused to validate issuers against different client information.
        /// </summary>
        /// <param name="issuer">The issuer value to validate.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a boolean
        /// indicating whether the issuer has been successfully validated. If the issuer is already validated and matches
        /// the stored client information, the validation is considered successful without further checks.</returns>
        /// <exception cref="InvalidOperationException">Thrown if attempting to validate a different issuer than the one
        /// associated with already stored client information.</exception>
        public async Task<bool> ValidateIssuer(string issuer)
        {
            switch (ClientInfo)
            {
                case { ClientId: var clientId } when issuer != clientId:
                    throw new InvalidOperationException(
                        $"Trying to validate issuer {issuer}, but already has info about client {clientId}");

                case not null:
                    return true;

                default:
                    var clientInfo = await _clientInfoProvider.TryFindClientAsync(issuer).WithLicenseCheck();
                    if (clientInfo is not { TokenEndpointAuthMethod: ClientAuthenticationMethods.PrivateKeyJwt })
                    {
                        return false;
                    }

                    ClientInfo = clientInfo;
                    return true;
            }
        }

        /// <summary>
        /// Asynchronously resolves the signing keys for a validated issuer's JWTs.
        /// </summary>
        /// <param name="issuer">The issuer URL whose signing keys are to be resolved.</param>
        /// <returns>An asynchronous stream of <see cref="JsonWebKey"/> objects representing the issuer's
        /// signing keys.</returns>
        public async IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeys(string issuer)
        {
            if (!await ValidateIssuer(issuer))
                yield break;

            await foreach (var key in _clientJwksProvider.GetSigningKeys(ClientInfo.NotNull(nameof(ClientInfo))))
                yield return key;
        }
    }
}
