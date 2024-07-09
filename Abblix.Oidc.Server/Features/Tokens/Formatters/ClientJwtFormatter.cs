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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Provides functionality to format JSON Web Tokens (JWTs) issued to clients by the authentication service.
/// This class handles the signing of JWTs and, if configured, their encryption, based on the needs of each client.
/// </summary>
public class ClientJwtFormatter : IClientJwtFormatter
{
    public ClientJwtFormatter(
        IJsonWebTokenCreator jwtCreator,
        IClientKeysProvider clientKeysProvider,
        IAuthServiceKeysProvider serviceKeysProvider)
    {
        _jwtCreator = jwtCreator;
        _clientKeysProvider = clientKeysProvider;
        _serviceKeysProvider = serviceKeysProvider;
    }

    private readonly IJsonWebTokenCreator _jwtCreator;
    private readonly IClientKeysProvider _clientKeysProvider;
    private readonly IAuthServiceKeysProvider _serviceKeysProvider;

    /// <summary>
    /// Asynchronously formats a JWT for a specific client, applying the necessary cryptographic operations
    /// based on the client's configuration and the authentication service's capabilities.
    /// </summary>
    /// <param name="token">The JSON Web Token (JWT) to be formatted for the client.</param>
    /// <param name="clientInfo">Information about the client to which the JWT is issued, including any requirements for encryption.</param>
    /// <returns>A <see cref="Task"/> that represents the asynchronous operation, resulting in a JWT string formatted and ready for use by the client.</returns>
    /// <remarks>
    /// This method ensures the JWT is signed with the appropriate key from the authentication service. If the client's configuration supports encryption,
    /// the method also encrypts the JWT using the client's public key. The result is a JWT that conforms to the security requirements of both
    /// the client and the authentication service.
    /// </remarks>
    public async Task<string> FormatAsync(JsonWebToken token, ClientInfo clientInfo)
    {
        var signingCredentials = await _serviceKeysProvider.GetSigningKeys(true)
            .FirstByAlgorithmAsync(token.Header.Algorithm);

        var encryptingCredentials = await _clientKeysProvider.GetEncryptionKeys(clientInfo)
            .FirstOrDefaultAsync();

        return await _jwtCreator.IssueAsync(token, signingCredentials, encryptingCredentials);
    }
}
