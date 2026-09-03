// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats dynamic client registration results (RFC 7591) as <see cref="IResult"/>: a 201 with the registered client
/// configuration on success, or the JSON OAuth error on failure.
/// </summary>
/// <param name="uriBuilder">Builds the <c>registration_client_uri</c> for the registered client.</param>
public class RegisterClientResponseFormatter(RegistrationClientUriBuilder uriBuilder) : IRegisterClientResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(
        ClientRegistrationRequest request, Result<ClientRegistrationSuccessResponse, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: success => FormatSuccess(request, success),
            onFailure: error => error.Format(StatusCodes.Status400BadRequest)));

    private IResult FormatSuccess(ClientRegistrationRequest request, ClientRegistrationSuccessResponse success)
    {
        var modelResponse = new ClientRegistrationResponse
        {
            ClientId = success.ClientId,
            ClientIdIssuedAt = success.ClientIdIssuedAt,

            ClientSecret = success.ClientSecret,
            ClientSecretExpiresAt = success.ClientSecretExpiresAt ?? DateTimeOffset.UnixEpoch,

            RegistrationAccessToken = success.RegistrationAccessToken,

            RegistrationClientUri = success.RegistrationAccessToken.HasValue()
                ? uriBuilder.Build(success.ClientId)
                : null,

            // RFC 7591 section 3.2.1: the response echoes the registered values (the server may default or narrow them),
            // not the literal request input.
            InitiateLoginUri = success.InitiateLoginUri ?? request.InitiateLoginUri,
            TokenEndpointAuthMethod = success.TokenEndpointAuthMethod ?? request.TokenEndpointAuthMethod,
            Scope = success.Scope ?? request.Scope,
            SoftwareId = request.SoftwareId,
            SoftwareVersion = request.SoftwareVersion,
            SoftwareStatement = request.SoftwareStatement,

            ApplicationType = success.ApplicationType,
            RedirectUris = success.RedirectUris,
            GrantTypes = success.GrantTypes,
            ResponseTypes = success.ResponseTypes,
            ClientName = success.ClientName,
            LogoUri = success.LogoUri,
            SubjectType = success.SubjectType,
            SectorIdentifierUri = success.SectorIdentifierUri,
            JwksUri = success.JwksUri,
            UserInfoEncryptedResponseAlg = success.UserInfoEncryptedResponseAlg,
            UserInfoEncryptedResponseEnc = success.UserInfoEncryptedResponseEnc,
            // RFC 9701 section 6 / RFC 7591 section 3.2.1: echo the registered introspection response algorithms.
            IntrospectionSignedResponseAlg = success.IntrospectionSignedResponseAlg,
            IntrospectionEncryptedResponseAlg = success.IntrospectionEncryptedResponseAlg,
            IntrospectionEncryptedResponseEnc = success.IntrospectionEncryptedResponseEnc,
            Contacts = success.Contacts,
            RequestUris = success.RequestUris,
            TlsClientAuthSubjectDn = success.TlsClientAuthSubjectDn,
            TlsClientAuthSanDns = success.TlsClientAuthSanDns,
            TlsClientAuthSanUri = success.TlsClientAuthSanUri,
            TlsClientAuthSanIp = success.TlsClientAuthSanIp,
            TlsClientAuthSanEmail = success.TlsClientAuthSanEmail,
            DpopBoundAccessTokens = success.DpopBoundAccessTokens,
            RequirePushedAuthorizationRequests = success.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = success.RequireSignedRequestObject,
            TlsClientCertificateBoundAccessTokens = success.TlsClientCertificateBoundAccessTokens,
            AuthorizationDetailsTypes = success.AuthorizationDetailsTypes,
            TokenExchangeSubjectTokenTypes = success.TokenExchangeSubjectTokenTypes,
            TokenExchangeAudiences = success.TokenExchangeAudiences,
        };

        return Results.Json(modelResponse, statusCode: StatusCodes.Status201Created);
    }
}
