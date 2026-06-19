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
using Abblix.Oidc.Server.Features.RandomGenerators;
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
    IRegistrationAccessTokenStore registrationAccessTokenStore,
    ITokenIdGenerator tokenIdGenerator,
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
            // RFC 9449 §5.2: dpop_bound_access_tokens — when omitted, defaults to false.
            RequireDPoP = model.DpopBoundAccessTokens ?? false,
            // RFC 9126 §6 / RFC 9101 §10.5 / RFC 8705 §3.4: per-client FAPI-grade enforcement
            // flags — RFC 7592 update is a full replacement, so omission resets them to false.
            RequirePushedAuthorizationRequests = model.RequirePushedAuthorizationRequests ?? false,
            RequireSignedRequestObject = model.RequireSignedRequestObject ?? false,
            TlsClientCertificateBoundAccessTokens = model.TlsClientCertificateBoundAccessTokens ?? false,
            // Abblix extension: the named security profile bundle (e.g. FAPI 2.0). RFC 7592 update is
            // a full replacement, so omission resets it to ClientSecurityProfile.None.
            SecurityProfile = ClientSecurityProfiles.Parse(model.SecurityProfile),
            // RFC 9396 §5.1: authorization_details_types per-client allowlist.
            AuthorizationDetailsTypes = model.AuthorizationDetailsTypes,
            // Non-standard extension: RFC 8693 Token Exchange per-client subject-token-type allowlist.
            TokenExchangeAllowedSubjectTokenTypes = model.TokenExchangeSubjectTokenTypes,
            // Non-standard extension: RFC 8693 Token Exchange per-client audience allowlist (default-deny).
            TokenExchangeAllowedAudiences = model.TokenExchangeAudiences,
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
            AuthorizationEncryptedResponseAlgorithm = model.AuthorizationEncryptedResponseAlg,
            AuthorizationEncryptedResponseEncryption = model.AuthorizationEncryptedResponseEnc,
            RequestObjectSigningAlgorithm = model.RequestObjectSigningAlg,
            RequestObjectEncryptionAlgorithm = model.RequestObjectEncryptionAlg,
            RequestObjectEncryptionMethod = model.RequestObjectEncryptionEnc,
            TokenEndpointAuthSigningAlgorithm = model.TokenEndpointAuthSigningAlg,
            RequestUris = model.RequestUris ?? [],
            // RFC 7592 update is a full replacement: these must be re-applied or the update silently
            // drops them. Omitting AllowedScopes in particular reverted the client to "any scope"
            // (null = unrestricted), defeating the per-client scope enforcement on the update path.
            AllowedScopes = model.Scope,
            SoftwareId = model.SoftwareId,
            SoftwareVersion = model.SoftwareVersion,
        };

        if (model.AuthorizationSignedResponseAlg.HasValue())
        {
            updatedClient.AuthorizationSignedResponseAlgorithm = model.AuthorizationSignedResponseAlg;
        }

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
        if (model.TokenEndpointAuthMethod == ClientAuthenticationMethods.TlsClientAuth)
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

        // RFC 7592 §5: rotate the registration access token on update. Recording a fresh jti
        // invalidates every token issued before this update, limiting the exposure window of a
        // leaked token to the period between rotations.
        var registrationAccessTokenId = tokenIdGenerator.GenerateTokenId();
        await registrationAccessTokenStore.SetTokenIdAsync(updatedClient.ClientId, registrationAccessTokenId);

        // Generate response with new registration_access_token, embedding the freshly rotated jti.
        var issuedAt = clock.GetUtcNow();
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            updatedClient.ClientId,
            issuedAt,
            null,
            registrationAccessTokenId);

        return new ReadClientSuccessfulResponse
        {
            ClientId = updatedClient.ClientId,
            ClientSecret = null, // Client secrets are stored as hashes and cannot be retrieved
            ClientSecretExpiresAt = GetClientSecretExpiresAt(updatedClient),
            RegistrationAccessToken = registrationAccessToken,
            TokenEndpointAuthMethod = updatedClient.TokenEndpointAuthMethod,
            ApplicationType = updatedClient.ApplicationType,
            RedirectUris = updatedClient.RedirectUris,
            // RFC 7592 §3: echo the post-update registered state so the client can verify the
            // full replacement took effect (grant/response types and scope included).
            GrantTypes = updatedClient.AllowedGrantTypes,
            ResponseTypes = updatedClient.AllowedResponseTypes,
            Scope = updatedClient.AllowedScopes,
            RequirePushedAuthorizationRequests = updatedClient.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = updatedClient.RequireSignedRequestObject,
            TlsClientCertificateBoundAccessTokens = updatedClient.TlsClientCertificateBoundAccessTokens,
            SecurityProfile = ClientSecurityProfiles.ToWire(updatedClient.SecurityProfile),
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
            // RFC 9449 §5.2: echo dpop_bound_access_tokens so the client can confirm the
            // current binding state.
            DpopBoundAccessTokens = updatedClient.RequireDPoP,
            // RFC 9396 §5.1: echo authorization_details_types so the client confirms its allowlist.
            AuthorizationDetailsTypes = updatedClient.AuthorizationDetailsTypes,
            // Non-standard extension: echo token_exchange_subject_token_types.
            TokenExchangeSubjectTokenTypes = updatedClient.TokenExchangeAllowedSubjectTokenTypes,
            // Non-standard extension: echo token_exchange_audiences.
            TokenExchangeAudiences = updatedClient.TokenExchangeAllowedAudiences,
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
