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
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Default <see cref="IAuthorizationResponseEncoder"/>: resolves the client, builds the JARM response JWT,
/// signs it with the authorization server's key and — when the client registered an encryption algorithm —
/// additionally encrypts it to the client's public key (a Nested JWT per JARM §2.2).
/// </summary>
/// <param name="clientInfoProvider">Resolves the client the response is intended for.</param>
/// <param name="jwtCreator">Issues the signed/encrypted JWT.</param>
/// <param name="clientKeysProvider">Resolves the client's public encryption keys.</param>
/// <param name="serviceKeysProvider">Resolves the authorization server's signing keys.</param>
/// <param name="issuerProvider">Supplies the issuer identifier placed in the <c>iss</c> claim.</param>
/// <param name="timeProvider">Supplies the current time for the <c>iat</c>/<c>exp</c> claims.</param>
public class AuthorizationResponseEncoder(
    IClientInfoProvider clientInfoProvider,
    IJsonWebTokenCreator jwtCreator,
    IClientKeysProvider clientKeysProvider,
    IAuthServiceKeysProvider serviceKeysProvider,
    IIssuerProvider issuerProvider,
    TimeProvider timeProvider) : IAuthorizationResponseEncoder
{
    /// <summary>
    /// The maximum lifetime of a JARM response JWT. JARM §2.1 RECOMMENDS a maximum of 10 minutes; the
    /// authorization response is consumed by the client immediately upon redirect, so a short window suffices.
    /// </summary>
    private static readonly TimeSpan ResponseLifetime = TimeSpan.FromMinutes(10);

    /// <inheritdoc />
    public async Task<string> EncodeAsync(string? clientId, IReadOnlyList<(string name, string? value)> parameters)
    {
        var clientInfo = (await clientInfoProvider.TryFindClientAsync(clientId.NotNull(nameof(clientId))))
            .NotNull(nameof(ClientInfo));

        var now = timeProvider.GetUtcNow();

        var token = new JsonWebToken
        {
            Header = { Algorithm = clientInfo.AuthorizationSignedResponseAlgorithm },
            Payload =
            {
                IssuedAt = now,
                ExpiresAt = now + ResponseLifetime,
                Issuer = issuerProvider.GetIssuer(),
                Audiences = [clientInfo.ClientId],
            },
        };

        foreach (var (name, value) in parameters)
        {
            if (value != null)
                token.Payload[name] = value;
        }

        var signingCredentials = await serviceKeysProvider.GetSigningKeys(true)
            .FirstByAlgorithmAsync(token.Header.Algorithm);

        // JARM §2.2 / §3: encrypt only when the client registered authorization_encrypted_response_alg.
        // Otherwise the response is signed only.
        if (clientInfo.AuthorizationEncryptedResponseAlgorithm is not { } keyEncryptionAlgorithm)
            return await jwtCreator.IssueAsync(token, signingCredentials);

        var encryptingCredentials = await clientKeysProvider.GetEncryptionKeys(clientInfo)
            .FirstOrDefaultAsync();

        // JARM §3: when authorization_encrypted_response_enc is omitted the default is A128CBC-HS256.
        var contentEncryptionAlgorithm = clientInfo.AuthorizationEncryptedResponseEncryption
            ?? EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256;

        return await jwtCreator.IssueAsync(
            token,
            signingCredentials,
            encryptingCredentials,
            keyEncryptionAlgorithm,
            contentEncryptionAlgorithm);
    }
}
