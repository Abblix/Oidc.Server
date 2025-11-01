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
public class ClientSecretJwtAuthenticator(
    ILogger<ClientSecretJwtAuthenticator> logger,
    IJsonWebTokenValidator tokenValidator,
    IClientInfoProvider clientInfoProvider,
    IRequestInfoProvider requestInfoProvider,
    IHashService hashService) : IClientAuthenticator
{
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
