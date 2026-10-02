// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Builds the <see cref="ClientInfo"/> stored for a dynamically managed client from its registration metadata
/// (Builder). A registration (RFC 7591) and its full replacement (RFC 7592 section 2.2) assemble the client the
/// same way, so a field mapped for one cannot be forgotten by the other; they differ only in what they carry
/// over from elsewhere - the secrets and the sector identifier.
/// </summary>
/// <param name="clientId">The identifier of the client being built.</param>
/// <param name="model">The registration metadata the client is built from.</param>
internal sealed class ClientInfoBuilder(string clientId, ClientRegistrationRequest model)
{
    private string? _sectorIdentifier;
    private ClientSecret[]? _clientSecrets;

    /// <summary>
    /// Sets the sector identifier the client's pairwise subjects are computed under.
    /// </summary>
    public ClientInfoBuilder WithSectorIdentifier(string? sectorIdentifier)
    {
        _sectorIdentifier = sectorIdentifier;
        return this;
    }

    /// <summary>
    /// Sets the secrets the client authenticates with.
    /// </summary>
    public ClientInfoBuilder WithClientSecrets(ClientSecret[]? clientSecrets)
    {
        _clientSecrets = clientSecrets;
        return this;
    }

    /// <summary>
    /// Builds the client from the registration metadata and whatever was set on this builder.
    /// </summary>
    public ClientInfo Build()
    {
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets = _clientSecrets,
            SectorIdentifier = _sectorIdentifier,
        };

        ApplyFlowMetadata(clientInfo);
        ApplySecurityRequirements(clientInfo);
        ApplyDescriptiveMetadata(clientInfo);
        ApplyEncryptionAlgorithms(clientInfo);
        ApplySigningAlgorithms(clientInfo);
        ApplyLogout(clientInfo);
        ApplyTlsClientAuth(clientInfo);
        return clientInfo;
    }

    private void ApplyFlowMetadata(ClientInfo clientInfo)
    {
        clientInfo.TokenEndpointAuthMethod = model.TokenEndpointAuthMethod;
        clientInfo.AllowedResponseTypes = model.ResponseTypes;
        clientInfo.AllowedGrantTypes = model.GrantTypes;

        // A client that registers none has none: the flows that redirect are the ones that require
        // them, and a device-flow or CIBA client runs neither. Empty rather than null so every reader
        // downstream - the authorization endpoint's redirect check among them - sees a set to compare
        // against instead of having to ask whether there is one. RFC 7592 section 2 replaces the whole
        // metadata set, so a client dropping its redirect URIs on update ends up with an empty set too.
        clientInfo.RedirectUris = model.RedirectUris ?? [];
        clientInfo.PostLogoutRedirectUris = model.PostLogoutRedirectUris;
        clientInfo.RequestUris = model.RequestUris ?? [];

        // RFC 7592 update is a full replacement: the scope must be re-applied, or an update omitting it
        // would revert the client to "any scope" (null = unrestricted) and defeat per-client scope enforcement.
        clientInfo.AllowedScopes = model.Scope;
        clientInfo.OfflineAccessAllowed = model.OfflineAccessAllowed;
        clientInfo.ApplicationType = model.ApplicationType;
        clientInfo.SubjectType = model.SubjectType;
        clientInfo.DefaultMaxAge = model.DefaultMaxAge;
        clientInfo.RequireAuthTime = model.RequireAuthTime;
        clientInfo.DefaultAcrValues = model.DefaultAcrValues;

        clientInfo.BackChannelTokenDeliveryMode = model.BackChannelTokenDeliveryMode;
        clientInfo.BackChannelClientNotificationEndpoint = model.BackChannelClientNotificationEndpoint;
        clientInfo.BackChannelAuthenticationRequestSigningAlg = model.BackChannelAuthenticationRequestSigningAlg;
        clientInfo.BackChannelUserCodeParameter = model.BackChannelUserCodeParameter;

        // RFC 9396 section 10: authorization_details_types per-client allowlist.
        clientInfo.AuthorizationDetailsTypes = model.AuthorizationDetailsTypes;
        // Non-standard extension: RFC 8693 Token Exchange per-client subject-token-type allowlist.
        clientInfo.TokenExchangeAllowedSubjectTokenTypes = model.TokenExchangeSubjectTokenTypes;
        // Non-standard extension: RFC 8693 Token Exchange per-client audience allowlist (default-deny).
        clientInfo.TokenExchangeAllowedAudiences = model.TokenExchangeAudiences;
    }

    private void ApplySecurityRequirements(ClientInfo clientInfo)
    {
        clientInfo.Jwks = model.Jwks;
        clientInfo.JwksUri = model.JwksUri;
        clientInfo.PkceRequired = model.PkceRequired;

        // RFC 9449 section 5.2: dpop_bound_access_tokens - when omitted, defaults to false.
        clientInfo.RequireDPoP = model.DpopBoundAccessTokens ?? false;

        // RFC 9126 section 6 / RFC 9101 section 10.5 / RFC 8705 section 3.4: per-client FAPI-grade enforcement
        // flags - when omitted, default to false, which an RFC 7592 full-replacement update resets them to.
        clientInfo.RequirePushedAuthorizationRequests = model.RequirePushedAuthorizationRequests ?? false;
        clientInfo.RequireSignedRequestObject = model.RequireSignedRequestObject ?? false;
        clientInfo.TlsClientCertificateBoundAccessTokens = model.TlsClientCertificateBoundAccessTokens ?? false;
    }

    private void ApplyDescriptiveMetadata(ClientInfo clientInfo)
    {
        clientInfo.ClientName = model.ClientName;
        clientInfo.ClientUri = model.ClientUri;
        clientInfo.LogoUri = model.LogoUri;
        clientInfo.PolicyUri = model.PolicyUri;
        clientInfo.TermsOfServiceUri = model.TermsOfServiceUri;
        clientInfo.InitiateLoginUri = model.InitiateLoginUri;
        clientInfo.Contacts = model.Contacts;
        clientInfo.SoftwareId = model.SoftwareId;
        clientInfo.SoftwareVersion = model.SoftwareVersion;
    }

    private void ApplyEncryptionAlgorithms(ClientInfo clientInfo)
    {
        clientInfo.IdentityTokenEncryptedResponseAlgorithm = model.IdTokenEncryptedResponseAlg;
        clientInfo.IdentityTokenEncryptedResponseEncryption = model.IdTokenEncryptedResponseEnc;
        clientInfo.UserInfoEncryptedResponseAlgorithm = model.UserInfoEncryptedResponseAlg;
        clientInfo.UserInfoEncryptedResponseEncryption = model.UserInfoEncryptedResponseEnc;
        clientInfo.IntrospectionEncryptedResponseAlgorithm = model.IntrospectionEncryptedResponseAlg;
        clientInfo.IntrospectionEncryptedResponseEncryption = model.IntrospectionEncryptedResponseEnc;
        clientInfo.AuthorizationEncryptedResponseAlgorithm = model.AuthorizationEncryptedResponseAlg;
        clientInfo.AuthorizationEncryptedResponseEncryption = model.AuthorizationEncryptedResponseEnc;
        clientInfo.RequestObjectSigningAlgorithm = model.RequestObjectSigningAlg;
        clientInfo.RequestObjectEncryptionAlgorithm = model.RequestObjectEncryptionAlg;
        clientInfo.RequestObjectEncryptionMethod = model.RequestObjectEncryptionEnc;
        clientInfo.TokenEndpointAuthSigningAlgorithm = model.TokenEndpointAuthSigningAlg;
    }

    /// <summary>
    /// Applies only the signed-response algorithms the registration states.
    /// </summary>
    /// <remarks>
    /// These have non-null <see cref="ClientInfo"/> defaults (id_token and authorization response RS256,
    /// userinfo and introspection none), so an omitted value keeps the default rather than overwriting it
    /// with null and breaking the client's token signatures.
    /// </remarks>
    private void ApplySigningAlgorithms(ClientInfo clientInfo)
    {
        if (model.IdTokenSignedResponseAlg.HasValue())
            clientInfo.IdentityTokenSignedResponseAlgorithm = model.IdTokenSignedResponseAlg;

        if (model.UserInfoSignedResponseAlg.HasValue())
            clientInfo.UserInfoSignedResponseAlgorithm = model.UserInfoSignedResponseAlg;

        if (model.IntrospectionSignedResponseAlg.HasValue())
            clientInfo.IntrospectionSignedResponseAlgorithm = model.IntrospectionSignedResponseAlg;

        if (model.AuthorizationSignedResponseAlg.HasValue())
            clientInfo.AuthorizationSignedResponseAlgorithm = model.AuthorizationSignedResponseAlg;
    }

    private void ApplyLogout(ClientInfo clientInfo)
    {
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
    }

    private void ApplyTlsClientAuth(ClientInfo clientInfo)
    {
        if (model.TokenEndpointAuthMethod != ClientAuthenticationMethods.TlsClientAuth)
            return;

        clientInfo.TlsClientAuth = new ()
        {
            SubjectDn = model.TlsClientAuthSubjectDn,
            SanDns = model.TlsClientAuthSanDns,
            SanUris = model.TlsClientAuthSanUri,
            SanIps = model.TlsClientAuthSanIp,
            SanEmails = model.TlsClientAuthSanEmail,
        };
    }
}
