// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// - Client secrets cannot be updated via this endpoint
    /// </remarks>
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(ValidUpdateClientRequest request)
    {
        var existingClient = request.Client.ClientInfo;

        // RFC 7592 section 2.2 replaces the metadata but not the credentials, so the client's secrets are kept
        // rather than updated here; the sector identifier the pairwise subjects hang on is kept too.
        var updatedClient = new ClientInfoBuilder(existingClient.ClientId, request.RegistrationRequest)
            .WithSectorIdentifier(existingClient.SectorIdentifier)
            .WithClientSecrets(existingClient.ClientSecrets)
            .Build();

        // The response echoes the post-update registered state, so what the store now holds is the
        // answer - RFC 7592 section 3 asks the client to be able to verify that the full replacement
        // took effect.
        // RFC 7592 section 5: rotate the registration access token on update. Recording a fresh jti
        // invalidates every token issued before this update, limiting the exposure window of a
        // leaked token to the period between rotations. The replacement takes effect only on the
        // registration this request was authenticated against: one rotated or removed meanwhile is
        // left as it is, and the token that decided the change no longer manages anything.
        var registrationAccessTokenId = tokenIdGenerator.GenerateTokenId();

        // The new registration_access_token, embedding the freshly rotated jti, is issued before the
        // rotation is stored: issuing stores nothing, so a failure to issue leaves the token the client
        // holds working rather than rotating it away for one never delivered.
        var issuedAt = clock.GetUtcNow();
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            updatedClient.ClientId,
            issuedAt,
            null,
            registrationAccessTokenId);

        if (!await clientInfoManager.TryUpdateClientAsync(
                request.Client, new RegisteredClient(updatedClient, registrationAccessTokenId)))
        {
            return new OidcError(ErrorCodes.InvalidToken, "The access token unauthorized");
        }

        return new ReadClientSuccessfulResponse
        {
            ClientId = updatedClient.ClientId,
            ClientSecret = null, // The update issues no new secret, so there is none to return
            ClientSecretExpiresAt = GetClientSecretExpiresAt(updatedClient),
            RegistrationAccessToken = registrationAccessToken,
            TokenEndpointAuthMethod = updatedClient.TokenEndpointAuthMethod,
            ApplicationType = updatedClient.ApplicationType,
            RedirectUris = updatedClient.RedirectUris,
            // RFC 7592 section 3: echo the post-update registered state so the client can verify the
            // full replacement took effect (grant/response types and scope included).
            GrantTypes = updatedClient.EffectiveGrantTypes,
            ResponseTypes = updatedClient.EffectiveResponseTypes,
            Scope = updatedClient.AllowedScopes,
            RequirePushedAuthorizationRequests = updatedClient.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = updatedClient.RequireSignedRequestObject,
            TlsClientCertificateBoundAccessTokens = updatedClient.TlsClientCertificateBoundAccessTokens,
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
            // RFC 9449 section 5.2: echo dpop_bound_access_tokens so the client can confirm the
            // current binding state.
            DpopBoundAccessTokens = updatedClient.RequireDPoP,
            // RFC 9396 section 10: echo authorization_details_types so the client confirms its allowlist.
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
