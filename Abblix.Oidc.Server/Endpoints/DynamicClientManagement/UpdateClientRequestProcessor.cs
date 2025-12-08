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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Processes requests to update existing client configurations per RFC 7592 Section 2.2.
/// Updates client metadata while preserving credentials and system-managed fields.
/// </summary>
public class UpdateClientRequestProcessor(
    IClientInfoManager clientInfoManager,
    IRegistrationAccessTokenService registrationAccessTokenService,
    TimeProvider clock) : IUpdateClientRequestProcessor
{
    /// <summary>
    /// Processes a valid update client request, updating client metadata and returning updated configuration.
    /// </summary>
    /// <param name="request">The validated update request containing new client metadata.</param>
    /// <returns>A task that results in updated client configuration or an error response.</returns>
    /// <remarks>
    /// Per RFC 7592:
    /// - All client metadata can be updated except client_id, client_secret, and issuance timestamps
    /// - Omitted fields are treated as null/empty
    /// - A new registration_access_token may be issued
    /// - Client secrets cannot be updated via this endpoint (they're stored as hashes)
    /// </remarks>
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidUpdateClientRequest request)
    {
        var model = request.RegistrationRequest;
        var existingClient = request.ClientInfo;

        // Create updated client info, preserving immutable fields
        var updatedClient = new ClientInfo(existingClient.ClientId)
        {
            // Preserve client secrets (cannot be updated per RFC 7592)
            ClientSecrets = existingClient.ClientSecrets,

            // Update metadata from request
            TokenEndpointAuthMethod = model.TokenEndpointAuthMethod,
            AllowedResponseTypes = model.ResponseTypes,
            AllowedGrantTypes = model.GrantTypes,
            RedirectUris = model.RedirectUris,
            Jwks = model.Jwks,
            JwksUri = model.JwksUri,
            PkceRequired = model.PkceRequired,
            OfflineAccessAllowed = model.OfflineAccessAllowed,
            LogoUri = model.LogoUri,
            PolicyUri = model.PolicyUri,
            TermsOfServiceUri = model.TermsOfServiceUri,
            InitiateLoginUri = model.InitiateLoginUri,
            SubjectType = model.SubjectType,
            SectorIdentifier = existingClient.SectorIdentifier, // Preserve existing sector identifier
            PostLogoutRedirectUris = model.PostLogoutRedirectUris,
            BackChannelTokenDeliveryMode = model.BackChannelTokenDeliveryMode,
            BackChannelClientNotificationEndpoint = model.BackChannelClientNotificationEndpoint,
            BackChannelAuthenticationRequestSigningAlg = model.BackChannelAuthenticationRequestSigningAlg,
            BackChannelUserCodeParameter = model.BackChannelUserCodeParameter,
            ApplicationType = model.ApplicationType,
            Contacts = model.Contacts,
            ClientName = model.ClientName,
            ClientUri = model.ClientUri,
            DefaultMaxAge = model.DefaultMaxAge,
            RequireAuthTime = model.RequireAuthTime,
            DefaultAcrValues = model.DefaultAcrValues,
            IdentityTokenEncryptedResponseAlgorithm = model.IdTokenEncryptedResponseAlg,
            IdentityTokenEncryptedResponseEncryption = model.IdTokenEncryptedResponseEnc,
            UserInfoEncryptedResponseAlgorithm = model.UserInfoEncryptedResponseAlg,
            UserInfoEncryptedResponseEncryption = model.UserInfoEncryptedResponseEnc,
            RequestObjectSigningAlgorithm = model.RequestObjectSigningAlg,
            RequestObjectEncryptionAlgorithm = model.RequestObjectEncryptionAlg,
            RequestObjectEncryptionMethod = model.RequestObjectEncryptionEnc,
            TokenEndpointAuthSigningAlgorithm = model.TokenEndpointAuthSigningAlg,
            RequestUris = model.RequestUris ?? [],
        };

        // Update logout configuration using wrapper objects
        if (model.BackChannelLogoutUri != null)
        {
            updatedClient.BackChannelLogout = new (
                model.BackChannelLogoutUri,
                model.BackChannelLogoutSessionRequired ?? false);
        }

        if (model.FrontChannelLogoutUri != null)
        {
            updatedClient.FrontChannelLogout = new (
                model.FrontChannelLogoutUri,
                model.FrontChannelLogoutSessionRequired ?? false);
        }

        // Map tls_client_auth metadata if selected
        if (string.Equals(model.TokenEndpointAuthMethod, ClientAuthenticationMethods.TlsClientAuth, StringComparison.Ordinal))
        {
            updatedClient.TlsClientAuth = new()
            {
                SubjectDn = model.TlsClientAuthSubjectDn,
                SanDns = model.TlsClientAuthSanDns,
                SanUris = model.TlsClientAuthSanUri,
                SanIps = model.TlsClientAuthSanIp,
                SanEmails = model.TlsClientAuthSanEmail,
            };
        }

        // Update client in storage
        await clientInfoManager.UpdateClientAsync(updatedClient);

        // Generate response with new registration_access_token
        var issuedAt = clock.GetUtcNow();
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            updatedClient.ClientId,
            issuedAt,
            null);

        return new ReadClientSuccessfulResponse
        {
            ClientId = updatedClient.ClientId,
            ClientSecret = null, // Client secrets are stored as hashes and cannot be retrieved
            ClientSecretExpiresAt = GetClientSecretExpiresAt(updatedClient),
            RegistrationAccessToken = registrationAccessToken,
            TokenEndpointAuthMethod = updatedClient.TokenEndpointAuthMethod,
            ApplicationType = updatedClient.ApplicationType,
            RedirectUris = updatedClient.RedirectUris,
            ClientName = updatedClient.ClientName,
            LogoUri = updatedClient.LogoUri,
            SubjectType = updatedClient.SubjectType,
            SectorIdentifierUri = Uri.TryCreate(updatedClient.SectorIdentifier, UriKind.Absolute, out var uri) ? uri : null,
            JwksUri = updatedClient.JwksUri,
            UserInfoEncryptedResponseAlg = updatedClient.UserInfoEncryptedResponseAlgorithm,
            UserInfoEncryptedResponseEnc = updatedClient.UserInfoEncryptedResponseEncryption,
            Contacts = updatedClient.Contacts,
            RequestUris = updatedClient.RequestUris,
            InitiateLoginUri = updatedClient.InitiateLoginUri,
            // tls_client_auth metadata (if configured)
            TlsClientAuthSubjectDn = updatedClient.TlsClientAuth?.SubjectDn,
            TlsClientAuthSanDns = updatedClient.TlsClientAuth?.SanDns,
            TlsClientAuthSanUri = updatedClient.TlsClientAuth?.SanUris,
            TlsClientAuthSanIp = updatedClient.TlsClientAuth?.SanIps,
            TlsClientAuthSanEmail = updatedClient.TlsClientAuth?.SanEmails,
        };
    }

    /// <summary>
    /// Determines the latest expiration time among all client secrets.
    /// </summary>
    private static DateTimeOffset? GetClientSecretExpiresAt(ClientInfo client)
    {
        if (client.ClientSecrets == null)
            return null;

        DateTimeOffset? result = null;
        foreach (var secretExpiresAt in client.ClientSecrets.Select(s => s.ExpiresAt))
        {
            if (!secretExpiresAt.HasValue)
                continue;

            if (!result.HasValue || result.Value < secretExpiresAt.Value)
                result = secretExpiresAt;
        }

        return result;
    }
}
