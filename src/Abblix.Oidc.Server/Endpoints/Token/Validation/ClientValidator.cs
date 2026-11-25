// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Validation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Validates the client information in the context of a token request, ensuring that the client is properly authenticated.
/// </summary>
/// <remarks>
/// This validator is responsible for authenticating the client making the token request. It leverages the
/// <see cref="IClientAuthenticator"/> to perform the authentication, and if successful, attaches the client information
/// to the validation context. If the authentication fails, it returns an error indicating that the client is not authorized.
/// </remarks>
/// <param name="clientAuthenticator">The client authenticator used to authenticate the client.</param>
/// <param name="clientInfoProvider">The client store, asked through a lookup made for each request.</param>
/// <param name="jwtReader">Reads the client a refresh token presented without client_id was issued to.</param>
public class ClientValidator(
    IClientAuthenticator clientAuthenticator,
    IClientInfoProvider clientInfoProvider,
    IAuthServiceJwtReader jwtReader)
    : ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the client in the token request context. This method checks if the client
    /// can be authenticated using the provided client request information. If the client is successfully authenticated,
    /// the client information is added to the context; otherwise, an error is returned.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">The validation context containing the token request and client information.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the client cannot be authenticated,
    /// otherwise null indicating successful validation.
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, TokenValidationContext context, CancellationToken cancellationToken)
    {
        var clientRequest = context.ClientRequest;

        // RFC 6749 section 5.2: a request that "includes multiple credentials, utilizes more than one mechanism for
        // authenticating the client" is an invalid_request. Decided before the authenticator, which has only
        // invalid_client to say and would count the request as a failed attempt
        if (clientRequest.HasMoreThanOneAuthorizationHeader)
            return ErrorFactory.MoreThanOneAuthorizationHeader;

        // One lookup of the clients for the whole request, handed on to the steps that read a token it presents
        var clients = new RequestScopedClientInfoProvider(clientInfoProvider);
        context.Clients = clients;

        // The client a refresh token presented without any credential names is the one authenticated, once: a first
        // attempt without it would be charged to the source as a failed one, which a working client must never be.
        // Asking what is presented first refuses a source past its failure budget before the token's signature is checked
        if (!(await clientAuthenticator.FindPresentedCredentialsAsync(tenant, clientRequest, clients)).Any() &&
            await NamedByTheRefreshTokenAsync(tenant, context.Request, clientRequest, clients) is { } named)
        {
            clientRequest = named;
        }

        var authenticated = await clientAuthenticator.TryAuthenticateClientAsync(tenant, clientRequest, clients);

        if (!authenticated.TryGetSuccess(out var clientInfo))
        {
            // RFC 6749 section 5.2 names a request that "utilizes more than one mechanism for authenticating the
            // client" an invalid_request, not a failed authentication. draft-ietf-oauth-client-id-metadata-document-03
            // section 6.1: "for a transient failure, an HTTP 503". A later step reading a token of another client may
            // meet that client's outage too, but the answer to such a token does not depend on it, so only a failed
            // authentication is answered as one
            return clients.RefusalOf(authenticated.GetFailure() as MoreThanOneClientAuthenticationMethodError
                                     ?? BasicChallenge.InvalidClient(clientRequest, "The client is not authorized"));
        }

        context.ClientInfo = clientInfo;
        return null;
    }

    /// <summary>
    /// <paramref name="clientRequest"/> naming the client the refresh token of <paramref name="request"/> was issued
    /// to, for a refresh token request presenting no credential and no client_id, or null where it names none.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.2: client_id is "needed when a form of client authentication
    /// that relies on the parameter is used, or the grant_type requires identification of public clients", and the
    /// refresh token grant does not: section 4.3.1 has the server check the token against client_id only "if a
    /// client_id is included in the request", the token being "bound to the client to which it was issued". The client
    /// it names is then authenticated as a request naming it would be, so only a client of the method none is served
    /// so, and a confidential one still has to authenticate ("Confidential clients MUST authenticate"). The token is
    /// only read here, its lifetime aside and nothing recorded about it, for the client it names: the grant validates
    /// it, answering an expired one invalid_grant as it does for a request naming its client, and spends it.
    /// </remarks>
    private async Task<ClientRequest?> NamedByTheRefreshTokenAsync(
        TenantDefinition tenant,
        TokenRequest request,
        ClientRequest clientRequest,
        IClientInfoProvider clients)
    {
        if (request is not { GrantType: GrantTypes.RefreshToken, RefreshToken: { Length: > 0 } refreshToken } ||
            clientRequest.ClientId.HasValue())
        {
            return null;
        }

        var token = await jwtReader.ReadAuthenticAsync(
            tenant,
            client: null,
            clients,
            refreshToken,
            TokenTypePolicy.Exactly(JwtTypes.RefreshToken),
            ServiceTokenValidation.AnyAudience & ~ValidationOptions.ValidateLifetime);

        if (!token.TryGetSuccess(out var readToken) || readToken.OwnerOf() is not { Length: > 0 } clientId)
            return null;

        return clientRequest with { ClientId = clientId };
    }
}
