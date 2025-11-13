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
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the processing of requests to retrieve stored client information, ensuring that such requests
/// are valid and authorized. This class serves as a bridge between the request validation and the actual
/// retrieval of client details from the system's data store.
/// </summary>
public class ReadClientRequestProcessor(
    IRegistrationAccessTokenService registrationAccessTokenService,
    IIssuerProvider issuerProvider,
    TimeProvider clock) : IReadClientRequestProcessor
{
    /// <summary>
    /// Asynchronously retrieves the details of a client based on a valid request.
    /// This method ensures that only authorized and valid requests lead to the disclosure of client information.
    /// </summary>
    /// <param name="request">A <see cref="ValidClientRequest"/> object containing the identification details
    /// of the client whose information is being requested.</param>
    /// <returns>
    /// A <see cref="Task"/> that, upon completion, yields a <see cref="ReadClientSuccessfulResponse"/> containing the details
    /// of the client. The response includes information such as the client's ID, redirect URIs, and the URL for
    /// initiating login, among other possible client configuration details.
    /// </returns>
    /// <remarks>
    /// This method is essential for supporting features like dynamic client registration and management in OAuth 2.0
    /// and OpenID Connect ecosystems. It allows clients or administrators to query the system for the configuration
    /// of registered clients, facilitating transparency and ease of management. Note that sensitive information,
    /// like client secrets, are not directly retrievable to maintain security.
    /// </remarks>
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request)
    {
        var client = request.ClientInfo;

        var issuer = issuerProvider.GetIssuer();
        var registrationClientUri = new Uri(new Uri(issuer), $"register/{client.ClientId}");

        var issuedAt = clock.GetUtcNow();
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(client.ClientId, issuedAt, null);

        return new ReadClientSuccessfulResponse
        {
            ClientId = client.ClientId,
            ClientSecret = null, // Client secrets are stored as hashes and cannot be retrieved
            ClientSecretExpiresAt = GetClientSecretExpiresAt(client),
            RegistrationClientUri = registrationClientUri,
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
