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
public class ClientJwtValidator: IClientJwtValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientJwtValidator"/> class.
    /// </summary>
    /// <param name="logger">The logger used for recording validation activities and outcomes.</param>
    /// <param name="requestInfoProvider">Provides information about the current request, including the request URI.
    /// </param>
    /// <param name="tokenValidator">The service used to perform core JWT validation.</param>
    /// <param name="clientInfoProvider">Provides access to client information for validation purposes.</param>
    /// <param name="clientJwksProvider">Provides access to the client's JSON Web Keys (JWKs) for verifying signatures.
    /// </param>
    public ClientJwtValidator(
        ILogger<ClientJwtValidator> logger,
        IRequestInfoProvider requestInfoProvider,
        IJsonWebTokenValidator tokenValidator,
        IClientInfoProvider clientInfoProvider,
        IClientKeysProvider clientJwksProvider)
    {
        _logger = logger;
        _clientInfoProvider = clientInfoProvider;
        _clientJwksProvider = clientJwksProvider;
        _requestInfoProvider = requestInfoProvider;
        _tokenValidator = tokenValidator;
    }

    private readonly ILogger _logger;
    private readonly IRequestInfoProvider _requestInfoProvider;
    private readonly IJsonWebTokenValidator _tokenValidator;
    private readonly IClientInfoProvider _clientInfoProvider;
    private readonly IClientKeysProvider _clientJwksProvider;

    /// <summary>
    /// Validates the JWT issued by a client, ensuring that it meets the expected criteria for issuer, audience,
    /// and cryptographic signatures. This method is used in scenarios such as private JWT client authentication
    /// and request object validation.
    /// </summary>
    /// <param name="jwt">The JWT to validate.</param>
    /// <param name="options">Options to customize the validation process.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result is a tuple containing the validation result
    /// and the associated client information if the issuer is validated.
    /// </returns>
    public async Task<(JwtValidationResult, ClientInfo?)> ValidateAsync(
        string jwt,
        ValidationOptions options = ValidationOptions.Default)
    {
        var result = await _tokenValidator.ValidateAsync(
            jwt,
            new ValidationParameters
            {
                Options = options,
                ValidateAudience = ValidateAudience,
                ValidateIssuer = ValidateIssuer,
                ResolveIssuerSigningKeys = ResolveIssuerSigningKeys,
            });

        return (result, ClientInfo);
    }

    /// <summary>
    /// Holds client information after the issuer has been successfully validated.
    /// </summary>
    private ClientInfo? ClientInfo { get; set; }

    /// <summary>
    /// Validates the audience by checking if it matches the request URI.
    /// </summary>
    /// <param name="audiences">The collection of audiences to validate against the request URI.</param>
    /// <returns>A task that represents the asynchronous operation. The task result indicates whether
    /// the audience is valid.</returns>
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
    /// Validates the issuer by attempting to match it with known client information. Ensures that the JWT issuer
    /// corresponds to an authorized client, and handles scenarios where client information is already known.
    /// </summary>
    /// <param name="issuer">The issuer value to validate.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result indicates whether the issuer is valid
    /// and corresponds to an authorized client.
    /// </returns>
    /// <exception cref="InvalidOperationException">Thrown if attempting to validate a different issuer than the one
    /// associated with the stored client information.</exception>
    private async Task<bool> ValidateIssuer(string issuer)
    {
        switch (ClientInfo)
        {
            // Case where client information is already known and the issuer matches the client ID.
            case { ClientId: var clientId } when issuer == clientId:
                return true;

            // Case where client information is already known, but the issuer does not match the known client ID.
            case { ClientId: var clientId }:
                throw new InvalidOperationException(
                    $"Trying to validate issuer {issuer}, but already has info about client {clientId}");

            // Case where client information is not yet known; attempt to find the client by issuer.
            case null:
                ClientInfo = await _clientInfoProvider.TryFindClientAsync(issuer).WithLicenseCheck();

                // If the client is found but does not use the expected authentication method, validation fails.
                return ClientInfo != null;
        }
    }

    /// <summary>
    /// Asynchronously resolves the signing keys for a validated issuer's JWTs, allowing the authentication service
    /// to verify the JWT signature.
    /// </summary>
    /// <param name="issuer">The issuer URL whose signing keys are to be resolved.</param>
    /// <returns>An asynchronous stream of <see cref="JsonWebKey"/> objects representing the issuer's signing keys.
    /// </returns>
    private async IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeys(string issuer)
    {
        if (!await ValidateIssuer(issuer))
            yield break;

        var clientInfo = ClientInfo.NotNull(nameof(ClientInfo));
        await foreach (var key in _clientJwksProvider.GetSigningKeys(clientInfo))
            yield return key;
    }
}
