// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using UriBuilder = Abblix.Utils.UriBuilder;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The pages the server leaves to its host, for the one tenant the host serves.
/// </summary>
/// <param name="tenant">The tenant the pending requests and sign-ins belong to.</param>
public sealed class ConformancePages(TenantDefinition tenant)
{
    /// <summary>
    /// Maps the pages the host serves itself beside the protocol endpoints: sign-in, the end user's answer to a CIBA
    /// request, and the operator's key rotation.
    /// </summary>
    /// <param name="endpoints">The application's endpoints.</param>
    public void MapTo(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/login", async (
                string request_uri,
                IAuthorizationRequestStorage pendingRequests,
                IClientInfoProvider clients) =>
            Results.Content(
                LoginPage.Render(request_uri, error: null, await PendingClientAsync(request_uri, pendingRequests, clients)),
                "text/html"));

        // The operator's part of the suite's key rotation module, called by the run script between the module's two
        // reads of the published key set; this host is reachable only on the suite's network
        endpoints.MapPost("/conformance/rotate-keys", () =>
        {
            RotatingSigningKeys.Rotate();
            return Results.NoContent();
        });

        // The end user's answer on their device to a pending CIBA request, given by the suite in the user's place
        endpoints.MapPost(FapiPlanFamily.CibaApprovalPath, async (
                string auth_req_id,
                string action,
                IBackChannelRequestStorage storage,
                IAuthenticationCompletionHandler completion,
                TimeProvider clock) =>
            await ConformanceUserDevice.AnswerAsync(tenant, auth_req_id, action, storage, completion, clock)
                ? Results.NoContent()
                : Results.NotFound());

        endpoints.MapPost("/login", async (
                [FromForm] string email,
                [FromForm] string password,
                [FromForm] string requestUri,
                [FromForm] string? action,
                IAuthSessionService authService,
                IOidcEndpointResolver endpointResolver,
                ISessionIdGenerator sessionIdGenerator,
                TimeProvider timeProvider,
                IAuthorizationRequestStorage pendingRequests,
                IClientInfoProvider clients,
                ConformanceUser conformanceUser) =>
            {
                if (!conformanceUser.Matches(email, password))
                {
                    var client = await PendingClientAsync(requestUri, pendingRequests, clients);
                    return Results.Content(
                        LoginPage.Render(requestUri, "Invalid email or password", client), "text/html");
                }

                // The server keeps only the sessions at a level the request asked for, so a sign-in recording none
                // would be sent straight back here. A password is the one factor this host has, and it is taken as
                // whichever level the client named first.
                var pending = await pendingRequests.TryGetAsync(tenant, new Uri(requestUri));
                var sessionId = sessionIdGenerator.GenerateSessionId();

                switch (action)
                {
                    case "allow":
                        break;

                    // Refusing still takes the user's sign-in: the server asks for consent only of a signed-in user,
                    // and a consent granting nothing is how the refusal reaches the client
                    case "deny":
                        RefusedAuthorizations.RefuseIn(sessionId);
                        break;

                    default:
                        return Results.BadRequest("The action is neither allow nor deny");
                }

                await authService.SignInAsync(new AuthSession(
                    ConformanceUser.Subject,
                    sessionId,
                    timeProvider.GetUtcNow(),
                    CookieAuthenticationDefaults.AuthenticationScheme)
                {
                    AuthContextClassRef = pending?.AcrValues?.FirstOrDefault(),
                });

                var authorizeUrl = new UriBuilder(endpointResolver.Resolve(OidcEndpoints.Authorize)!)
                    { Query = { [AuthorizationRequest.Parameters.RequestUri] = requestUri } };
                return Results.Redirect(authorizeUrl);
            })
            // The single-use request_uri the form carries already binds the post to the pending authorization request
            .DisableAntiforgery();
    }

    // The client the pending authorization request is for, whose name, logo, policy and terms the login page shows
    private async Task<ClientInfo?> PendingClientAsync(
        string requestUri,
        IAuthorizationRequestStorage pendingRequests,
        IClientInfoProvider clients)
    {
        var pending = await pendingRequests.TryGetAsync(tenant, new Uri(requestUri));
        return pending?.ClientId is { } clientId ? await clients.TryFindClientAsync(tenant, clientId) : null;
    }
}
