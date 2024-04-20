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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

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
