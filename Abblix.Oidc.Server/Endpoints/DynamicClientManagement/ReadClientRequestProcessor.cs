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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Builds the RFC 7592 §2.1 read-client response from stored client metadata. The
/// <c>client_secret</c> is intentionally omitted because secrets are persisted only as
/// hashes; a fresh <c>registration_access_token</c> is issued so the client can keep using
/// the management endpoint after the read.
/// </summary>
public class ReadClientRequestProcessor(
    IRegistrationAccessTokenService registrationAccessTokenService,
    TimeProvider clock) : IReadClientRequestProcessor
{
    /// <inheritdoc />
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request)
    {
        var client = request.ClientInfo;

        var issuedAt = clock.GetUtcNow();
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(client.ClientId, issuedAt, null);

        return new ReadClientSuccessfulResponse
        {
            ClientId = client.ClientId,
            ClientSecret = null, // Client secrets are stored as hashes and cannot be retrieved
            ClientSecretExpiresAt = GetClientSecretExpiresAt(client),
            RegistrationAccessToken = registrationAccessToken,
            TokenEndpointAuthMethod = client.TokenEndpointAuthMethod,
            ApplicationType = client.ApplicationType,
            RedirectUris = client.RedirectUris,
            ClientName = client.ClientName,
            LogoUri = client.LogoUri,
            SubjectType = client.SubjectType,
            SectorIdentifierUri = Uri.TryCreate(client.SectorIdentifier, UriKind.Absolute, out var uri) ? uri : null,
            JwksUri = client.JwksUri,
            UserInfoEncryptedResponseAlg = client.UserInfoEncryptedResponseAlgorithm,
            UserInfoEncryptedResponseEnc = client.UserInfoEncryptedResponseEncryption,
            Contacts = client.Contacts,
            RequestUris = client.RequestUris,
            InitiateLoginUri = client.InitiateLoginUri,
            // tls_client_auth metadata (if configured)
            TlsClientAuthSubjectDn = client.TlsClientAuth?.SubjectDn,
            TlsClientAuthSanDns = client.TlsClientAuth?.SanDns,
            TlsClientAuthSanUri = client.TlsClientAuth?.SanUris,
            TlsClientAuthSanIp = client.TlsClientAuth?.SanIps,
            TlsClientAuthSanEmail = client.TlsClientAuth?.SanEmails,
        };
    }

    /// <summary>
    /// Determines the latest expiration time among all client secrets.
    /// </summary>
    /// <param name="client">The client information containing secret configurations.</param>
    /// <returns>
    /// The latest expiration time if any secrets have expiration dates; otherwise, null.
    /// Returns null if the client has no secrets or all secrets have no expiration.
    /// </returns>
    private static DateTimeOffset? GetClientSecretExpiresAt(ClientInfo client)
    {
        if (client.ClientSecrets == null)
            return null;

        DateTimeOffset? result = null;
        foreach (var expiresAt in client.ClientSecrets.Select(secret => secret.ExpiresAt))
        {
            if (!expiresAt.HasValue)
                continue;

            if (!result.HasValue || result.Value < expiresAt.Value)
                result = expiresAt;
        }

        return result;
    }
}
