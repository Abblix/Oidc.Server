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
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for client registration responses.
/// </summary>
/// <param name="uriResolver">The action URI provider used for generating URIs for client management actions.</param>
public class RegisterClientResponseFormatter(IUriResolver uriResolver) : IRegisterClientResponseFormatter
{
    /// <summary>
    /// Formats a client registration response asynchronously, converting the response model to an appropriate
    /// <see cref="ActionResult"/> based on the nature of the response.
    /// </summary>
    /// <param name="request">The client registration request containing the data submitted by the client.</param>
    /// <param name="response">The client registration response model to be formatted.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// Depending on the response, this may be a success result with client details or an error response.
    /// </returns>
    /// <remarks>
    /// This method handles different types of responses: successful registration and error scenarios.
    /// In the case of successful registration, it returns a 201 Created response with client details.
    /// In the case of an error, it returns a 400 Bad Request response with error details.
    /// </remarks>
    public Task<ActionResult> FormatResponseAsync(
        ClientRegistrationRequest request,
        Result<ClientRegistrationSuccessResponse, OidcError> response)
    {
        return Task.FromResult(response.Match(
            onSuccess: success => FormatSuccess(request, success),
            onFailure: error => error.Format(StatusCodes.Status400BadRequest)));
    }

    private ActionResult FormatSuccess(ClientRegistrationRequest request, ClientRegistrationSuccessResponse success)
    {
        var modelResponse = new ClientRegistrationResponse
        {
            ClientId = success.ClientId,
            ClientIdIssuedAt = success.ClientIdIssuedAt,

            ClientSecret = success.ClientSecret,
            ClientSecretExpiresAt = success.ClientSecretExpiresAt ?? DateTimeOffset.UnixEpoch,

            RegistrationAccessToken = success.RegistrationAccessToken,

            RegistrationClientUri = success.RegistrationAccessToken.HasValue()
                ? GetClientReadUrl(success.ClientId)
                : null,

            // Prefer the resolved server-side value from `success` (which reflects defaults
            // applied by the registration pipeline) over the raw request - RFC 7591 section 3.2.1
            // requires the response to echo registered values, not the literal request input.
            InitiateLoginUri = success.InitiateLoginUri ?? request.InitiateLoginUri,
            TokenEndpointAuthMethod = success.TokenEndpointAuthMethod ?? request.TokenEndpointAuthMethod,

            // RFC 7591 section 3.2.1: scope echoes the registered value (the server may narrow or default
            // it), not the literal request input.
            Scope = success.Scope ?? request.Scope,
            SoftwareId = request.SoftwareId,
            SoftwareVersion = request.SoftwareVersion,
            SoftwareStatement = request.SoftwareStatement,

            // RFC 7591 section 3.2.1: echo registered metadata so clients can confirm what was stored.
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
            // RFC 9449 section 5.2: dpop_bound_access_tokens echo.
            DpopBoundAccessTokens = success.DpopBoundAccessTokens,
            // RFC 9126 section 6 / RFC 9101 section 10.5 / RFC 8705 section 3.4: per-client enforcement flags echo.
            RequirePushedAuthorizationRequests = success.RequirePushedAuthorizationRequests,
            RequireSignedRequestObject = success.RequireSignedRequestObject,
            TlsClientCertificateBoundAccessTokens = success.TlsClientCertificateBoundAccessTokens,
            // RFC 9396 section 10: authorization_details_types echo.
            AuthorizationDetailsTypes = success.AuthorizationDetailsTypes,
            // Non-standard extension: token_exchange_subject_token_types echo.
            TokenExchangeSubjectTokenTypes = success.TokenExchangeSubjectTokenTypes,
            // Non-standard extension: token_exchange_audiences echo.
            TokenExchangeAudiences = success.TokenExchangeAudiences,
        };

        return new ObjectResult(modelResponse) { StatusCode = StatusCodes.Status201Created };
    }

    private Uri GetClientReadUrl(string clientId) => uriResolver.Action(
        MvcUtils.TrimAsync(nameof(ClientManagementController.ReadClientAsync)),
        MvcUtils.NameOf<ClientManagementController>(),
        new RouteValueDictionary
        {
            { "clientId", clientId },
        });
}
