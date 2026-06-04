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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the registration of new clients by generating the necessary credentials and adding client information to
/// the system. Ensures the secure and compliant registration of clients as per OAuth 2.0 and OpenID Connect standards.
/// </summary>
public class RegisterClientRequestProcessor(
    IClientCredentialFactory credentialFactory,
    IClientInfoManager clientInfoManager,
    TimeProvider clock,
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

        await clientInfoManager.AddClientAsync(clientInfo);

        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            credentials.ClientId,
            issuedAt,
            clientInfo.ExpiresAfter);

        var response = new ClientRegistrationSuccessResponse(
            credentials.ClientId,
            issuedAt,
            registrationAccessToken)
        {
            ClientSecret = credentials.ClientSecret,
            ClientSecretExpiresAt = credentials.ExpiresAt,
            // RFC 7591 §3.2.1: echo registered metadata so the client can confirm what was
            // registered (including server-assigned defaults) without a follow-up read.
            TokenEndpointAuthMethod = clientInfo.TokenEndpointAuthMethod,
            ApplicationType = clientInfo.ApplicationType,
            RedirectUris = clientInfo.RedirectUris,
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
            AuthorizationDetailsTypes = clientInfo.AuthorizationDetailsTypes,
            TokenExchangeSubjectTokenTypes = clientInfo.TokenExchangeAllowedSubjectTokenTypes,
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
    {
        var clientInfo = new ClientInfo(credentials.ClientId)
        {
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
            // RFC 9396 §5.1: authorization_details_types per-client allowlist.
            AuthorizationDetailsTypes = model.AuthorizationDetailsTypes,
            // Non-standard extension: RFC 8693 Token Exchange per-client subject-token-type allowlist.
            TokenExchangeAllowedSubjectTokenTypes = model.TokenExchangeSubjectTokenTypes,
            LogoUri = model.LogoUri,
            PolicyUri = model.PolicyUri,
            TermsOfServiceUri = model.TermsOfServiceUri,
            InitiateLoginUri = model.InitiateLoginUri,
            SubjectType = model.SubjectType,
            SectorIdentifier = sectorIdentifier,
            PostLogoutRedirectUris = model.PostLogoutRedirectUris,
            BackChannelTokenDeliveryMode = model.BackChannelTokenDeliveryMode,
            BackChannelClientNotificationEndpoint = model.BackChannelClientNotificationEndpoint,
            BackChannelAuthenticationRequestSigningAlg = model.BackChannelAuthenticationRequestSigningAlg,
            BackChannelUserCodeParameter = model.BackChannelUserCodeParameter,
            AllowedScopes = model.Scope,
            SoftwareId = model.SoftwareId,
            SoftwareVersion = model.SoftwareVersion,
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
            IntrospectionEncryptedResponseAlgorithm = model.IntrospectionEncryptedResponseAlg,
            IntrospectionEncryptedResponseEncryption = model.IntrospectionEncryptedResponseEnc,
            AuthorizationEncryptedResponseAlgorithm = model.AuthorizationEncryptedResponseAlg,
            AuthorizationEncryptedResponseEncryption = model.AuthorizationEncryptedResponseEnc,
            RequestObjectSigningAlgorithm = model.RequestObjectSigningAlg,
            RequestObjectEncryptionAlgorithm = model.RequestObjectEncryptionAlg,
            RequestObjectEncryptionMethod = model.RequestObjectEncryptionEnc,
            TokenEndpointAuthSigningAlgorithm = model.TokenEndpointAuthSigningAlg,
        };

        // Map tls_client_auth metadata if selected
        if (model.TokenEndpointAuthMethod == ClientAuthenticationMethods.TlsClientAuth)
        {
            clientInfo.TlsClientAuth = new ()
            {
                SubjectDn = model.TlsClientAuthSubjectDn,
                SanDns = model.TlsClientAuthSanDns,
                SanUris = model.TlsClientAuthSanUri,
                SanIps = model.TlsClientAuthSanIp,
                SanEmails = model.TlsClientAuthSanEmail,
            };
        }

        if (credentials.ClientSecret.HasValue())
        {
            clientInfo.ClientSecrets =
            [
                new ClientSecret
                {
                    Value = clientInfo.TokenEndpointAuthMethod switch
                    {
                        ClientAuthenticationMethods.ClientSecretJwt => credentials.ClientSecret,
                        _ => null,
                    },
                    Sha512Hash = credentials.Sha512Hash,
                    ExpiresAt = credentials.ExpiresAt,
                }
            ];
        }

        if (model.RequestUris != null)
        {
            clientInfo.RequestUris = model.RequestUris;
        }

        if (model.UserInfoSignedResponseAlg.HasValue())
        {
            clientInfo.UserInfoSignedResponseAlgorithm = model.UserInfoSignedResponseAlg;
        }

        if (model.IntrospectionSignedResponseAlg.HasValue())
        {
            clientInfo.IntrospectionSignedResponseAlgorithm = model.IntrospectionSignedResponseAlg;
        }

        if (model.IdTokenSignedResponseAlg.HasValue())
        {
            clientInfo.IdentityTokenSignedResponseAlgorithm = model.IdTokenSignedResponseAlg;
        }

        if (model.AuthorizationSignedResponseAlg.HasValue())
        {
            clientInfo.AuthorizationSignedResponseAlgorithm = model.AuthorizationSignedResponseAlg;
        }

        if (model.BackChannelLogoutUri != null)
        {
            clientInfo.BackChannelLogout = new (
                model.BackChannelLogoutUri,
                model.BackChannelLogoutSessionRequired ?? false);
        }

        if (model.FrontChannelLogoutUri != null)
        {
            clientInfo.FrontChannelLogout = new (
                model.FrontChannelLogoutUri,
                model.FrontChannelLogoutSessionRequired ?? false);
        }

        return clientInfo;
    }
}
