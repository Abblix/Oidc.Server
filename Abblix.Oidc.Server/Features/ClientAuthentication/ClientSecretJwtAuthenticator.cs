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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Authenticates client requests using the client_secret_jwt authentication method.
/// This method is used in scenarios where the client signs a JWT with its secret as a means of authentication.
/// </summary>
public class ClientSecretJwtAuthenticator : IClientAuthenticator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientSecretJwtAuthenticator"/> class.
    /// </summary>
    /// <param name="logger">Logger for logging authentication process information and warnings.</param>
    /// <param name="tokenValidator">Validator for JSON Web Tokens (JWT) used in client assertions.</param>
    /// <param name="clientInfoProvider">Provider for retrieving client information, essential for validating client identity.</param>
    /// <param name="requestInfoProvider">Provider for retrieving information about the current request, used in validating JWT claims like audience.</param>
    /// <param name="hashService">Service for hashing client secrets to compare with JWT signature.</param>
    public ClientSecretJwtAuthenticator(
        ILogger<ClientSecretJwtAuthenticator> logger,
        IJsonWebTokenValidator tokenValidator,
        IClientInfoProvider clientInfoProvider,
        IRequestInfoProvider requestInfoProvider,
        IHashService hashService)
    {
        _logger = logger;
        _tokenValidator = tokenValidator;
        _clientInfoProvider = clientInfoProvider;
        _requestInfoProvider = requestInfoProvider;
        _hashService = hashService;
    }

    private readonly ILogger _logger;
    private readonly IJsonWebTokenValidator _tokenValidator;
    private readonly IClientInfoProvider _clientInfoProvider;
    private readonly IRequestInfoProvider _requestInfoProvider;
    private readonly IHashService _hashService;

    /// <summary>
    /// Specifies the client authentication method this authenticator supports, which is 'client_secret_jwt'.
    /// This indicates that the authenticator handles client authentication using JSON Web Tokens (JWT) for
    /// the client secret, as defined in the OpenID Connect specification. It involves using JWTs as
    /// client credentials for authentication, where the JWT assertion is signed by the client's secret key.
    /// </summary>
    public IEnumerable<string> ClientAuthenticationMethodsSupported
    {
        get { yield return ClientAuthenticationMethods.ClientSecretJwt; }
    }

    /// <summary>
    /// Asynchronously tries to authenticate a client request using the client_secret_jwt method.
    /// Validates the JWT and checks if the client is authorized to use this authentication method.
    /// </summary>
    /// <param name="request">The client request to authenticate.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield the
    /// authenticated <see cref="ClientInfo"/>, or null if the authentication is unsuccessful.
    /// </returns>
    public Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
    {
        // Example implementation here. You'll need to adjust the logic according to your actual JWT validation process,
        // client information retrieval, and the specifics of how the client_secret_jwt is expected to work in your system.
        // This might involve verifying the JWT signature using the client's secret, checking the issuer, subject,
        // audience, and expiration of the JWT, and ensuring that the client is registered to use the client_secret_jwt method.

        //TODO implement client_secret_jwt

        return Task.FromResult<ClientInfo?>(null);
    }
}
