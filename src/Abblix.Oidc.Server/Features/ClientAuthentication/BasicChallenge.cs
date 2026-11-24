// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Whether a refusal of client authentication answers with a <c>WWW-Authenticate: Basic</c> challenge, the one answer
/// every endpoint authenticating clients gives.
/// </summary>
/// <remarks>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.4: "If the client attempted to authenticate via the Authorization
/// request header field ..., the authorization server MUST respond with a 401 (Unauthorized) status code and include
/// the WWW-Authenticate response header field ... matching the authentication scheme used by the client. Client
/// authentication methods that do not use an HTTP authentication scheme have no corresponding challenge". Basic is the
/// one HTTP scheme the server authenticates clients by, so the challenge is owed to a client that used it and to one
/// registered for it; any other is answered with its endpoint's own status and no challenge, since RFC 9110 section
/// 15.5.2 has a 401 "send a WWW-Authenticate header field containing at least one challenge".
/// </remarks>
internal static class BasicChallenge
{
    /// <summary>
    /// Whether a refusal of <paramref name="request"/>, whose client is <paramref name="client"/> where known, answers
    /// with the Basic challenge: the request authenticated by HTTP Basic, or the client is registered for
    /// <c>client_secret_basic</c>.
    /// </summary>
    /// <param name="request">The client authentication the request carries.</param>
    /// <param name="client">The client the request names, or null where none is known.</param>
    public static bool IsOwed(ClientRequest request, ClientInfo? client)
        => request.AuthorizationHeader.HasScheme(TokenTypes.Basic) ||
           client is not null &&
           ClientSecretAuthenticator.IsRegisteredFor(client, ClientAuthenticationMethods.ClientSecretBasic);

    /// <summary>
    /// <see cref="IsOwed(ClientRequest, ClientInfo?)"/> for a request whose client is not authenticated, looked up by
    /// the client_id it names through <paramref name="clients"/>, the lookup its authentication made.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The client authentication the request carries.</param>
    /// <param name="clients">The clients of the request being served.</param>
    public static async Task<bool> IsOwedAsync(
        TenantDefinition tenant,
        ClientRequest request,
        IClientInfoProvider clients)
    {
        if (IsOwed(request, client: null))
            return true;

        if (request.ClientId is not { Length: > 0 } clientId)
            return false;

        return (await clients.FindClientAsync(tenant, clientId)).TryGetSuccess(out var client) &&
               IsOwed(request, client);
    }

    /// <summary>
    /// The <c>invalid_client</c> refusal of <paramref name="request"/>, carrying whether the Basic challenge is owed.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The client authentication the request carries.</param>
    /// <param name="clients">The clients of the request being served.</param>
    /// <param name="description">What the refusal says.</param>
    public static async Task<OidcError> InvalidClientAsync(
        TenantDefinition tenant,
        ClientRequest request,
        IClientInfoProvider clients,
        string description)
        => new(ErrorCodes.InvalidClient, description)
        {
            BasicChallengeOwed = await IsOwedAsync(tenant, request, clients),
        };
}
