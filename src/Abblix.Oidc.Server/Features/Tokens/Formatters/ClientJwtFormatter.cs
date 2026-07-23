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
using Abblix.Oidc.Server.Common.Constants;
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
    /// Asynchronously formats a JWT for a specific client, inferring the encryption metadata from the token's
    /// header <c>typ</c> (id_token/logout_token vs. UserInfo).
    /// </summary>
    /// <param name="token">The JSON Web Token (JWT) to be formatted for the client.</param>
    /// <param name="clientInfo">Information about the client to which the JWT is issued, including any requirements for encryption.</param>
    /// <returns>A task that returns a JWT string formatted and ready for use by the client.</returns>
    [Obsolete("Use FormatAsync(JsonWebToken, ClientInfo, ClientJwtEncryption) with an explicit encryption policy. " +
              "This overload infers the policy from token.Header.Type and is kept for backward compatibility.")]
    public Task<string> FormatAsync(JsonWebToken token, ClientInfo clientInfo)
    {
        // The legacy contract picks the client's registered encryption metadata by JWT class: id_token and
        // logout_token use id_token_encrypted_response_*, everything else (UserInfo) uses userinfo_encrypted_response_*.
        var encryption = token.Header.Type switch
        {
            JwtTypes.IdToken or JwtTypes.LogoutToken => ClientJwtEncryption.ForIdentityToken(clientInfo, options.Value),
            _ => ClientJwtEncryption.ForUserInfo(clientInfo, options.Value),
        };

        return FormatAsync(token, clientInfo, encryption);
    }

    /// <summary>
    /// Asynchronously formats a JWT for a specific client, signing it with the authentication service's key chosen by
    /// the token's header algorithm and — per the supplied <paramref name="encryption"/> policy — optionally
    /// encrypting it to the client's registered public key.
    /// </summary>
    /// <param name="token">The JSON Web Token (JWT) to be formatted for the client.</param>
    /// <param name="clientInfo">Information about the client to which the JWT is issued.</param>
    /// <param name="encryption">The encryption policy: which registered client metadata governs encryption, the
    /// content-encryption default, and whether encryption requires a registered key-management algorithm.</param>
    /// <returns>A task that returns a JWT string formatted and ready for use by the client.</returns>
    public async Task<string> FormatAsync(JsonWebToken token, ClientInfo clientInfo, ClientJwtEncryption encryption)
    {
        var signingCredentials = await serviceKeysProvider.GetSigningKeys(true)
            .FirstByAlgorithmAsync(token.Header.Algorithm);

        // JARM §2.2 / §3 opt-in: when the policy requires a registered key-management algorithm and the client has
        // not registered one, the response is signed only — the client's encryption keys are not even resolved.
        if (encryption is { RequireRegisteredAlgorithm: true, KeyManagementAlgorithm: null })
            return await jwtCreator.IssueAsync(token, signingCredentials);

        var encryptingCredentials = await clientKeysProvider.GetEncryptionKeys(clientInfo)
            .FirstOrDefaultAsync();

        var keyEncryptionAlgorithm = encryptingCredentials?.Algorithm
            ?? encryption.KeyManagementAlgorithm
            ?? EncryptionAlgorithms.KeyManagement.RsaOaep256;

        var contentEncryptionAlgorithm = encryption.ContentEncryptionAlgorithm
            ?? encryption.DefaultContentEncryptionAlgorithm;

        return await jwtCreator.IssueAsync(
            token,
            signingCredentials,
            encryptingCredentials,
            keyEncryptionAlgorithm,
            contentEncryptionAlgorithm);
    }
}
