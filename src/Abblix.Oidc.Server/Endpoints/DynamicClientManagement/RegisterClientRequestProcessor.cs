// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the registration of new clients by generating the necessary credentials and adding client information to
/// the system. Ensures the secure and compliant registration of clients as per OAuth 2.0 and OpenID Connect standards.
/// </summary>
/// <param name="logger">Records a registration the client store did not keep.</param>
/// <param name="credentialFactory">Generates the client id and secret.</param>
/// <param name="clientInfoManager">Stores the registration with its registration access token id.</param>
/// <param name="clock">Provides the issue time.</param>
/// <param name="tokenIdGenerator">Generates the registration access token id.</param>
/// <param name="registrationAccessTokenService">Issues the registration access token.</param>
public partial class RegisterClientRequestProcessor(
    ILogger<RegisterClientRequestProcessor> logger,
    IClientCredentialFactory credentialFactory,
    IClientInfoManager clientInfoManager,
    TimeProvider clock,
    ITokenIdGenerator tokenIdGenerator,
    IRegistrationAccessTokenService registrationAccessTokenService) : IRegisterClientRequestProcessor
{
    /// <summary>
    /// Processes a valid client registration request, generating and storing the client's credentials and configuration.
    /// </summary>
    /// <param name="request">The client registration request containing the necessary details for registering
    /// a new client.</param>
    /// <returns>A task that results in a Result containing the client ID,
    /// client secret and registration access token, along with other registration details.</returns>
    /// <remarks>
    /// This method orchestrates the client registration process, starting from generating a unique client ID
    /// and secret (if required) to issuing a registration access token. It ensures that all registered clients
    /// are compliant with the system's security standards and the OAuth 2.0 and OpenID Connect protocols.
    /// The method also handles the storage of client information, facilitating future authentication and
    /// authorization processes.
    /// </remarks>
    public async Task<Result<ClientRegistrationSuccessResponse, OidcError>> ProcessAsync(ValidClientRegistrationRequest request)
    {
        var model = request.Model;

        var issuedAt = clock.GetUtcNow();
        var credentials = credentialFactory.Create(model.TokenEndpointAuthMethod, model.ClientId);
        var clientInfo = ToClientInfo(model, credentials, request.SectorIdentifier);

        // The registration holds the jti of its registration access token, so the management endpoint
        // accepts that token for this registration alone (RFC 7592 section 5).
        var registrationAccessTokenId = tokenIdGenerator.GenerateTokenId();

        // Issued before the client is stored: issuing stores nothing, though it signs the token, so a
        // failure to issue leaves no stored client that no token could manage, and a token for a
        // registration the store then refuses matches nothing and is never answered.
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            credentials.ClientId,
            issuedAt,
            clientInfo.ExpiresAfter,
            registrationAccessTokenId);

        // The response echoes the registered metadata, so what the store now holds is the answer -
        // RFC 7591 section 3.2.1 asks for the server-assigned defaults to be visible to the client. A
        // registration the store did not keep - one racing another under the same id, or, in a store
        // following reloads, one under an id the settings came to configure meanwhile - is refused as
        // a taken id is.
        if (!await clientInfoManager.TryAddClientAsync(new RegisteredClient(clientInfo, registrationAccessTokenId)))
        {
            LogRegistrationNotKept(credentials.ClientId);
            return Validation.ErrorFactory.InvalidClientMetadata(
                $"The client with id={credentials.ClientId} is already registered");
        }

        var response = new ClientRegistrationSuccessResponse(
            credentials.ClientId,
            issuedAt,
            registrationAccessToken)
        {
            ClientSecret = credentials.ClientSecret,
            ClientSecretExpiresAt = credentials.ExpiresAt,
            // RFC 7591 section 3.2.1: echo registered metadata so the client can confirm what was
            // registered (including server-assigned defaults) without a follow-up read.
            TokenEndpointAuthMethod = clientInfo.TokenEndpointAuthMethod,
            ApplicationType = clientInfo.ApplicationType,
            RedirectUris = clientInfo.RedirectUris,
            // RFC 7591 section 3.2.1: grant_types/response_types/scope are read back from the stored
            // ClientInfo, not from the request - this is what makes server-assigned defaults
            // (authorization_code / code when omitted) visible to the client.
            GrantTypes = clientInfo.EffectiveGrantTypes,
            ResponseTypes = clientInfo.EffectiveResponseTypes,
            Scope = clientInfo.AllowedScopes,
            ClientName = clientInfo.ClientName,
            LogoUri = clientInfo.LogoUri,
            SubjectType = clientInfo.SubjectType,
            SectorIdentifierUri = Uri.TryCreate(clientInfo.SectorIdentifier, UriKind.Absolute, out var sectorUri) ? sectorUri : null,
            JwksUri = clientInfo.JwksUri,
            UserInfoEncryptedResponseAlg = clientInfo.UserInfoEncryptedResponseAlgorithm,
            UserInfoEncryptedResponseEnc = clientInfo.UserInfoEncryptedResponseEncryption,

            // RFC 9701: echo the registered introspection response algorithms. The signed algorithm is omitted
            // when it is the implicit "none" default so the response only advertises an explicit opt-in.
            IntrospectionSignedResponseAlg = clientInfo.IntrospectionSignedResponseAlgorithm switch
            {
                SigningAlgorithms.None => null,
                _ => clientInfo.IntrospectionSignedResponseAlgorithm,
            },
            IntrospectionEncryptedResponseAlg = clientInfo.IntrospectionEncryptedResponseAlgorithm,
            IntrospectionEncryptedResponseEnc = clientInfo.IntrospectionEncryptedResponseEncryption,

            Contacts = clientInfo.Contacts,
            RequestUris = clientInfo.RequestUris,
            InitiateLoginUri = clientInfo.InitiateLoginUri,
            TlsClientAuthSubjectDn = clientInfo.TlsClientAuth?.SubjectDn,
            TlsClientAuthSanDns = clientInfo.TlsClientAuth?.SanDns,
            TlsClientAuthSanUri = clientInfo.TlsClientAuth?.SanUris,
            TlsClientAuthSanIp = clientInfo.TlsClientAuth?.SanIps,
            TlsClientAuthSanEmail = clientInfo.TlsClientAuth?.SanEmails,
            DpopBoundAccessTokens = clientInfo.RequireDPoP,
            RequirePushedAuthorizationRequests = clientInfo.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = clientInfo.RequireSignedRequestObject,
            TlsClientCertificateBoundAccessTokens = clientInfo.TlsClientCertificateBoundAccessTokens,
            AuthorizationDetailsTypes = clientInfo.AuthorizationDetailsTypes,
            TokenExchangeSubjectTokenTypes = clientInfo.TokenExchangeAllowedSubjectTokenTypes,
            TokenExchangeAudiences = clientInfo.TokenExchangeAllowedAudiences,
        };

        return response;
    }


    /// <summary>
    /// Converts the registration request and credentials into a ClientInfo entity for storage.
    /// </summary>
    private static ClientInfo ToClientInfo(
        ClientRegistrationRequest model,
        ClientCredentials credentials,
        string? sectorIdentifier)
        => new ClientInfoBuilder(credentials.ClientId, model)
            .WithSectorIdentifier(sectorIdentifier)
            .WithClientSecrets(ToClientSecrets(model.TokenEndpointAuthMethod, credentials))
            .Build();

    /// <summary>
    /// The secrets a newly registered client authenticates with, or null when its method uses none.
    /// </summary>
    /// <remarks>
    /// Only client_secret_jwt keeps the secret itself, since verifying the client's HMAC-signed assertion
    /// needs it; every other method is verified against the hash.
    /// </remarks>
    private static ClientSecret[]? ToClientSecrets(string tokenEndpointAuthMethod, ClientCredentials credentials)
    {
        if (!credentials.ClientSecret.HasValue())
            return null;

        return
        [
            new ClientSecret
            {
                Value = tokenEndpointAuthMethod switch
                {
                    ClientAuthenticationMethods.ClientSecretJwt => credentials.ClientSecret,
                    _ => null,
                },
                Sha512Hash = credentials.Sha512Hash,
                ExpiresAt = credentials.ExpiresAt,
            }
        ];
    }
}
