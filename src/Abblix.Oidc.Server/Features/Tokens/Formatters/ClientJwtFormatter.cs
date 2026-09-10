// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
public class ClientJwtFormatter(
    IJsonWebTokenCreator jwtCreator,
    IClientKeysProvider clientKeysProvider,
    IAuthServiceKeysProvider serviceKeysProvider) : IClientJwtFormatter
{
    /// <summary>
    /// Asynchronously formats a JWT for a specific client, signing it with the authentication service's key chosen by
    /// the token's header algorithm and - per the supplied <paramref name="encryption"/> policy - optionally
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

        // JARM section 2.2 / section 3 opt-in: when the policy requires a registered key-management algorithm and the client has
        // not registered one, the response is signed only - the client's encryption keys are not even resolved.
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
