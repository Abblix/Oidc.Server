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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Provides functionality to format JSON Web Tokens (JWTs) issued to clients by the authentication service.
/// This class handles the signing of JWTs and, if configured, their encryption, based on the needs of each client.
/// </summary>
/// <param name="jwtCreator">Creator for issuing JWTs.</param>
/// <param name="clientKeysProvider">Provider for client encryption keys.</param>
/// <param name="serviceKeysProvider">Provider for service signing keys.</param>
/// <param name="options">OIDC configuration options.</param>
public class ClientJwtFormatter(
    IJsonWebTokenCreator jwtCreator,
    IClientKeysProvider clientKeysProvider,
    IAuthServiceKeysProvider serviceKeysProvider,
    IOptions<OidcOptions> options) : IClientJwtFormatter
{

    /// <summary>
    /// Asynchronously formats a JWT for a specific client, applying the necessary cryptographic operations
    /// based on the client's configuration and the authentication service's capabilities.
    /// </summary>
    /// <param name="token">The JSON Web Token (JWT) to be formatted for the client.</param>
    /// <param name="clientInfo">Information about the client to which the JWT is issued, including any requirements for encryption.</param>
    /// <returns>A task that returns a JWT string formatted and ready for use by the client.</returns>
    /// <remarks>
    /// This method ensures the JWT is signed with the appropriate key from the authentication service. If the client's configuration supports encryption,
    /// the method also encrypts the JWT using the client's public key and the client's preferred encryption algorithms.
    /// The result is a JWT that conforms to the security requirements of both the client and the authentication service.
    /// </remarks>
    public async Task<string> FormatAsync(JsonWebToken token, ClientInfo clientInfo)
    {
        var signingCredentials = await serviceKeysProvider.GetSigningKeys(true)
            .FirstByAlgorithmAsync(token.Header.Algorithm);

        var encryptingCredentials = await clientKeysProvider.GetEncryptionKeys(clientInfo)
            .FirstOrDefaultAsync();

        var keyEncryptionAlgorithm = encryptingCredentials?.Algorithm
            ?? clientInfo.IdentityTokenEncryptedResponseAlgorithm
            ?? EncryptionAlgorithms.KeyManagement.RsaOaep256;

        var contentEncryptionAlgorithm = clientInfo.IdentityTokenEncryptedResponseEncryption
            ?? options.Value.DefaultContentEncryptionAlgorithm;

        return await jwtCreator.IssueAsync(
            token,
            signingCredentials,
            encryptingCredentials,
            keyEncryptionAlgorithm,
            contentEncryptionAlgorithm);
    }
}
