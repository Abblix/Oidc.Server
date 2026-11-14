// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Provides functionality to format JSON Web Tokens (JWTs) issued to clients by the authentication service.
/// This class handles the signing of JWTs and, if configured, their encryption, based on the needs of each client.
/// </summary>
/// <param name="issuer">Issues the JWT once the client's profile admits its algorithms.</param>
/// <param name="clientKeysProvider">Provider for client encryption keys.</param>
/// <param name="serviceKeysProvider">Provider for service signing keys.</param>
public class ClientJwtFormatter(
    ProfiledJwtIssuer issuer,
    IClientKeysProvider clientKeysProvider,
    IAuthServiceKeysProvider serviceKeysProvider) : IClientJwtFormatter
{
    /// <summary>
    /// Asynchronously formats a JWT for a specific client, signing it with the authentication service's key chosen by
    /// the token's header algorithm and - per the supplied <paramref name="encryption"/> policy - optionally
    /// encrypting it to the client's registered public key.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="token">The JSON Web Token (JWT) to be formatted for the client.</param>
    /// <param name="clientInfo">Information about the client to which the JWT is issued.</param>
    /// <param name="encryption">The encryption policy: which registered client metadata governs encryption, the
    /// content-encryption default, and whether encryption requires a registered key-management algorithm.</param>
    /// <returns>A task that returns a JWT string formatted and ready for use by the client.</returns>
    public async Task<Result<string, OidcError>> FormatAsync(
        TenantDefinition tenant, JsonWebToken token, ClientInfo clientInfo, ClientJwtEncryption encryption)
    {
        var profile = SecurityProfileRequirements.For(tenant, clientInfo);
        var signingCredentials = await serviceKeysProvider.GetSigningKeys(tenant, true)
            .FirstByAlgorithmAsync(token.Header.Algorithm);

        // JARM section 2.2 / section 3 opt-in: when the policy requires a registered key-management algorithm and the client has
        // not registered one, the response is signed only - the client's encryption keys are not even resolved.
        if (encryption is { RequireRegisteredAlgorithm: true, KeyManagementAlgorithm: null })
            return await issuer.IssueAsync(profile, token, signingCredentials);

        // FAPI 1.0 Part 2 section 8.6.1: "For JWE, both clients and authorization servers shall not use the RSA1_5
        // algorithm". The key and the algorithm are chosen together, so a key the profile forbids is passed over, as is
        // one nothing can be encrypted to (a key declaring a signing algorithm, one the host did not register, or one
        // whose material the default algorithm does not fit); the keys sit at a jwks_uri the client can change after
        // registration, so this is decided here, where the key is chosen
        var defaultAlgorithm = NotForbidden(encryption.KeyManagementAlgorithm, profile.ForbidRsa1_5KeyManagement)
            ?? EncryptionAlgorithms.KeyManagement.RsaOaep256;
        var clientKeys = await clientKeysProvider.GetEncryptionKeys(clientInfo).ToArrayAsync();
        var (encryptingCredentials, keyEncryptionAlgorithm) = clientKeys
            .Select(key => (Key: key, Algorithm: issuer.EncryptionAlgorithmFor(profile, key, defaultAlgorithm)))
            .FirstOrDefault(candidate => candidate.Algorithm is not null);

        // A client that publishes encryption keys expects what is issued to it encrypted, so a token is not sent in
        // the clear because no key it publishes is one the server can use under its profile
        if (encryptingCredentials == null && clientKeys.Length > 0)
        {
            return new OidcError(
                ErrorCodes.InvalidClient,
                $"The key set of the client {clientInfo.ClientId} holds no encryption key the server can use under " +
                "its security profile");
        }

        var contentEncryptionAlgorithm = encryption.ContentEncryptionAlgorithm
            ?? encryption.DefaultContentEncryptionAlgorithm;

        return await issuer.IssueAsync(
            profile,
            token,
            signingCredentials,
            encryptingCredentials,
            keyEncryptionAlgorithm,
            contentEncryptionAlgorithm);
    }

    /// <summary>
    /// The registered key management algorithm, or null where it is RSA1_5 and the profile forbids it - which the
    /// client's configuration checks refuse before here, so it is reached only by a client stored with it.
    /// </summary>
    private static string? NotForbidden(string? algorithm, bool forbidRsa1_5)
        => forbidRsa1_5 && algorithm == EncryptionAlgorithms.KeyManagement.Rsa1_5 ? null : algorithm;
}
