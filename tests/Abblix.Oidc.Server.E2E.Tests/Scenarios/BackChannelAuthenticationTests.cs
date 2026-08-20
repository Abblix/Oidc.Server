// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using CibaResponse = Abblix.Oidc.Server.Model.BackChannelAuthenticationSuccess.Parameters;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using RegistrationResponse = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the CIBA backchannel authentication endpoint (OpenID Connect Client-Initiated
/// Backchannel Authentication Flow Core 1.0) against the real endpoint, the real request storage and the real
/// CIBA grant at the token endpoint.
/// </summary>
/// <remarks>
/// CIBA moves the whole user interaction off the browser: the client asks the provider to reach the user on
/// a separate device, then polls the token endpoint for the result. Nothing in the flow carries a
/// redirect_uri, a browser session or a user-present code, so the guarantees a normal authorization-code
/// flow gets for free from the user agent have to be enforced by the server on its own. That is where the
/// tests below sit.
///
/// The host already opts into the endpoint, but no test drove it. The files elsewhere in the suite that
/// mention "backchannel" are about back-channel logout, an unrelated feature.
///
/// The default host registers only the library's throwing stub for
/// <see cref="IUserDeviceAuthenticationHandler"/>, which is deliberate: CIBA cannot mint anything until an
/// integrator supplies the device interaction. Tests that need a real auth_req_id therefore build an isolated
/// host with a handler that accepts the user - so the request lands in storage as Pending, exactly the state
/// a real deployment sits in while it waits for the user to answer their phone.
/// </remarks>
public class BackChannelAuthenticationTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task An_auth_req_id_is_not_redeemable_before_the_user_authenticates()
    {
        // The whole point of CIBA is that issuing an auth_req_id is not consent - the user has not been asked
        // yet. A server that hands out tokens for a pending request lets any client that knows a phone number
        // or an email address mint an access token for that person without them ever touching a device.
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        var authRequestId = await InitiateAsync(client, discovery, ciba);

        var response = await RedeemAsync(client, discovery, ciba, authRequestId);
        var body = await ReadJsonAsync(response);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.AuthorizationPending, body[ResponseParameters.Error]!.GetValue<string>());

        // The half that matters: an error code alongside a usable token would be the breach this test exists
        // to catch.
        Assert.Null(body[ResponseParameters.AccessToken]);
    }

    [Fact]
    public async Task An_auth_req_id_cannot_be_redeemed_by_a_different_client()
    {
        // Nothing in a CIBA poll proves the caller is the client the user is being asked about - the
        // auth_req_id is the only handle, and it travels back to a client over an ordinary HTTP response.
        // Without an ownership check any registered client that obtained or guessed one could collect the
        // tokens the user approved for someone else.
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var initiator = await RegisterCibaClientAsync(client, discovery);
        var bystander = await RegisterCibaClientAsync(client, discovery);

        var authRequestId = await InitiateAsync(client, discovery, initiator);

        var response = await RedeemAsync(client, discovery, bystander, authRequestId);
        var body = await ReadJsonAsync(response);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, body[ResponseParameters.Error]!.GetValue<string>());
        Assert.Null(body[ResponseParameters.AccessToken]);
    }

    [Fact]
    public async Task A_request_without_a_user_hint_is_rejected()
    {
        // CIBA has no browser leg, so the hint is the only thing that names the person to be contacted.
        // A server that accepts a hintless request has to guess whom to authenticate, and any answer it
        // picks is an authentication attempt aimed at a user nobody asked for.
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterCibaClientAsync(client, discovery);

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [ClientRequest.Parameters.ClientId] = ciba.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
            });

        var body = await ReadJsonAsync(response);
        Assert.False(response.IsSuccessStatusCode, $"a hintless request must not be accepted: {body}");
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
        Assert.Null(body[CibaResponse.AuthenticationRequestId]);
    }

    [Fact]
    public async Task An_unauthenticated_request_does_not_start_an_authentication()
    {
        // This endpoint makes a user's device ring. Left open, it is a way to spam or phish any user whose
        // identifier an attacker knows, with the provider's own name on the prompt - and to enumerate which
        // identifiers exist. Client authentication is what keeps the prompt attributable to a known client.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
            });

        var body = await ReadJsonAsync(response);
        Assert.False(response.IsSuccessStatusCode, $"an unauthenticated request must not be accepted: {body}");
        Assert.Equal(ErrorCodes.UnauthorizedClient, body[ResponseParameters.Error]!.GetValue<string>());
        Assert.Null(body[CibaResponse.AuthenticationRequestId]);
    }

    [Fact]
    public async Task An_auth_req_id_that_was_never_issued_is_refused()
    {
        // A poll loop is a guessing oracle: the client is expected to hammer this grant, so a value the
        // server never issued must buy nothing. Accepting one would turn the CIBA grant into a way to
        // collect tokens by brute force rather than by asking a user.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.Ciba,
                [TokenRequest.Parameters.AuthenticationRequestId] = "an-auth-req-id-this-server-never-issued",
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            });

        var body = await ReadJsonAsync(response);
        Assert.False(response.IsSuccessStatusCode, $"an unknown auth_req_id must not be accepted: {body}");
        Assert.Null(body[ResponseParameters.AccessToken]);
    }

    [Fact]
    public async Task The_backchannel_authentication_endpoint_is_published_in_discovery()
    {
        // A CIBA client has no other way to find this endpoint - there is no browser to redirect and no
        // well-known path to fall back on. An endpoint that is enabled but unadvertised is unreachable.
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.BackChannelAuthenticationEndpoint);
    }

    /// <summary>The identifier the client passes to name the end-user to be contacted.</summary>
    private const string LoginHint = "e2e-subject";

    private sealed record CibaClient(string ClientId, string ClientSecret);

    /// <summary>
    /// Registers a client that is allowed to use the CIBA grant in poll mode. The pre-seeded test clients
    /// carry neither the grant nor a delivery mode, and the CIBA client validator rejects a client missing
    /// either, so dynamic registration is how a CIBA-capable client comes into existence here.
    /// </summary>
    /// <remarks>
    /// Two members here are pure ceremony for a CIBA client, both because the registration endpoint applies
    /// browser-flow defaults before any grant-aware validator can waive them. redirect_uris is marked
    /// required on the request model even though CIBA has no user-agent leg to redirect. response_types
    /// defaults to <c>code</c>, and the DCR consistency rule then demands the authorization_code grant
    /// alongside it, so it is cleared explicitly - a CIBA client returns no authorization response at all.
    /// </remarks>
    private static async Task<CibaClient> RegisterCibaClientAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            // No redirect_uris: CIBA moves the user interaction off the browser entirely, so there is no
            // redirect to register. That this registration is accepted is itself part of what the suite
            // proves.
            [RegistrationMembers.ClientName] = $"ciba-{Guid.NewGuid():N}",
            [RegistrationMembers.ResponseTypes] = new JsonArray(),
            [RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.Ciba),
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.BackChannelTokenDeliveryMode] = BackchannelTokenDeliveryModes.Poll,
        });

        return new CibaClient(
            registered[RegistrationResponse.ClientId]!.GetValue<string>(),
            registered[RegistrationResponse.ClientSecret]!.GetValue<string>());
    }

    /// <summary>
    /// Drives a well-formed backchannel authentication request and returns the issued auth_req_id, asserting
    /// the request was accepted so that a later assertion cannot pass against a flow that never started.
    /// </summary>
    private static async Task<string> InitiateAsync(
        HttpClient client, DiscoveryDocument discovery, CibaClient ciba)
    {
        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.BindingMessage] = "e2e-binding",
                [ClientRequest.Parameters.ClientId] = ciba.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
            });

        var body = await ReadJsonAsync(response);
        Assert.True(response.IsSuccessStatusCode,
            $"backchannel authentication should start, got {(int)response.StatusCode}: {body}");

        return body[CibaResponse.AuthenticationRequestId]!.GetValue<string>();
    }

    private static async Task<HttpResponseMessage> RedeemAsync(
        HttpClient client, DiscoveryDocument discovery, CibaClient ciba, string authRequestId) =>
        await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.Ciba,
            [TokenRequest.Parameters.AuthenticationRequestId] = authRequestId,
            [ClientRequest.Parameters.ClientId] = ciba.ClientId,
            [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
        });

    /// <summary>
    /// Builds an isolated host that can actually issue an auth_req_id, by supplying the device interaction
    /// the library leaves to the integrator: a handler that reports the canonical e2e user as reachable.
    /// </summary>
    /// <remarks>
    /// The polling interval is the shipped default here, deliberately. These tests each poll once, and a
    /// first poll is answered on its merits because the interval bounds the gap between polls - so what
    /// they exercise is the configuration a deployment actually runs. This host used to flatten the
    /// interval to zero, because the request was stamped with a next-poll time at issuance and the first
    /// poll came back <c>slow_down</c> instead of <c>authorization_pending</c>; that is what #281 changed,
    /// and the workaround left with it.
    /// </remarks>
    private WebApplicationFactory<Program> CreateCibaHost()
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Replace(ServiceDescriptor
                    .Scoped<IUserDeviceAuthenticationHandler, ReachableUserDeviceHandler>())));

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    /// <summary>
    /// Test double for the integrator-supplied device interaction. It reports that the user was reached and
    /// identifies them, which is what puts the stored request into the Pending state the tests poll against.
    /// It never reports the user as having answered, because that is precisely the state under test.
    /// </summary>
    private sealed class ReachableUserDeviceHandler(TimeProvider clock) : IUserDeviceAuthenticationHandler
    {
        public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
            ValidBackChannelAuthenticationRequest request)
            => Task.FromResult<Result<AuthSession, OidcError>>(new AuthSession(
                Subject: LoginHint,
                SessionId: Guid.NewGuid().ToString("N"),
                AuthenticationTime: clock.GetUtcNow(),
                IdentityProvider: "e2e-test"));
    }
}
