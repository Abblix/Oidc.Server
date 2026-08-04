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
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Builds the RFC 7592 §2.1 read-client response from stored client metadata. The
/// <c>client_secret</c> is intentionally omitted because secrets are persisted only as
/// hashes; a registration access token bearing the client's current jti is re-issued so the
/// client can keep using the management endpoint after the read, without invalidating the token
/// it presented (read stays idempotent - only update rotates the jti).
/// </summary>
public class ReadClientRequestProcessor(
    IRegistrationAccessTokenService registrationAccessTokenService,
    IRegistrationAccessTokenStore registrationAccessTokenStore,
    ITokenIdGenerator tokenIdGenerator,
    TimeProvider clock) : IReadClientRequestProcessor
{
    /// <inheritdoc />
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request)
    {
        var client = request.ClientInfo;

        var issuedAt = clock.GetUtcNow();
        // Reuse the stored jti so the token the client just presented stays valid; only update
        // rotates it (read is idempotent). A legacy client with no recorded jti gets a transient
        // one - it is not persisted here, so the binding stays unenforced for that client.
        var registrationAccessTokenId =
            await registrationAccessTokenStore.GetTokenIdAsync(client.ClientId) ?? tokenIdGenerator.GenerateTokenId();
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            client.ClientId, issuedAt, null, registrationAccessTokenId);

        return new ReadClientSuccessfulResponse
        {
            ClientId = client.ClientId,
            ClientSecret = null, // Client secrets are stored as hashes and cannot be retrieved
            ClientSecretExpiresAt = GetClientSecretExpiresAt(client),
            RegistrationAccessToken = registrationAccessToken,
            TokenEndpointAuthMethod = client.TokenEndpointAuthMethod,
            ApplicationType = client.ApplicationType,
            RedirectUris = client.RedirectUris,
            // RFC 7592 §3: the read response carries the full registered metadata, including the
            // grant/response types the server assigned by default when registration omitted them.
            GrantTypes = client.AllowedGrantTypes,
            ResponseTypes = client.AllowedResponseTypes,
            Scope = client.AllowedScopes,
            RequirePushedAuthorizationRequests = client.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = client.RequireSignedRequestObject,
            TlsClientCertificateBoundAccessTokens = client.TlsClientCertificateBoundAccessTokens,
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
            // RFC 7592 §3 requires the read response to carry all registered metadata; mirror the
            // update path so read and update return the identical surface for the same client.
            DpopBoundAccessTokens = client.RequireDPoP,
            AuthorizationDetailsTypes = client.AuthorizationDetailsTypes,
            TokenExchangeSubjectTokenTypes = client.TokenExchangeAllowedSubjectTokenTypes,
            TokenExchangeAudiences = client.TokenExchangeAllowedAudiences,
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
