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

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using DeviceRequest = Abblix.Oidc.Server.Model.DeviceAuthorizationRequest;
using DeviceResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;
using RegistrationRequest = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using RegistrationResponse = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the RFC 8628 Device Authorization Grant through the MVC adapter: the device
/// authorization endpoint that mints the code pair, and the token endpoint that redeems the device code.
/// </summary>
/// <remarks>
/// The device flow exists for input-constrained devices - a TV, a console, a printer - that cannot host a
/// browser. That shape moves the whole security burden onto two things: the device code must stay worthless
/// until a human has actually approved it on a second device, and the poll that redeems it must be tied to
/// the client that asked for it. A server that hands out tokens for an unapproved code turns every device
/// that merely started a flow into an authenticated session nobody consented to.
///
/// The E2E host has enabled the endpoint since the endpoint opt-in refactor, but no test drove it. None of
/// the pre-seeded clients carry the device grant, so these tests register their own through dynamic client
/// registration - which also gives each test a client of its own to prove the cross-client boundary.
/// </remarks>
public class DeviceAuthorizationTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task The_device_authorization_endpoint_is_published_in_discovery()
    {
        // A constrained device has no way to be told an endpoint URL out of band - discovery is how it finds
        // the endpoint at all. An endpoint that is enabled but unadvertised is unreachable in practice, and
        // the grant is equally unusable if a client cannot see that the server accepts it.
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.DeviceAuthorizationEndpoint);
        Assert.Contains(GrantTypes.DeviceAuthorization, discovery.GrantTypesSupported!);
    }

    [Fact]
    public async Task A_device_code_is_not_redeemable_before_the_user_approves_it()
    {
        // The single property the whole flow rests on. Between the code being issued and the user approving
        // it on a phone, the device polls the token endpoint continuously. If any of those polls returned
        // tokens, approval would be decorative: anyone who could start a device flow would hold a session
        // for the user, with no human ever having agreed to anything.
        //
        // Runs on an isolated host with the polling interval collapsed to zero. The shared host seeds the
        // first permitted poll one interval after issuance, so a poll there is throttled before the pending
        // check is ever reached - that throttle has its own test below. Removing the wait isolates the
        // approval gate itself.
        using var host = CreateHostWithoutPollingDelay();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var device = await RegisterDeviceClientAsync(client, discovery, "pending-poll");

        var authorization = await StartDeviceFlowAsync(client, discovery, device);
        var deviceCode = authorization[DeviceResponse.Parameters.DeviceCode]!.GetValue<string>();

        var response = await PollAsync(client, discovery, device, deviceCode);

        await AssertRefusedAsync(response, ErrorCodes.AuthorizationPending);

        // No token of any kind may ride along with the refusal. An error body that also carried an access
        // token would satisfy an error-code check and still hand over the session.
        var body = await ReadJsonAsync(response);
        Assert.Null(body[ResponseParameters.AccessToken]);
    }

    [Fact]
    public async Task A_device_code_that_was_never_issued_is_refused()
    {
        // The device code is a bearer credential the client polls with, so guessing one is the direct attack.
        // The server must refuse a code it never minted rather than treating an unknown value as approved.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var device = await RegisterDeviceClientAsync(client, discovery, "unknown-code");

        var response = await PollAsync(client, discovery, device, "a-device-code-this-server-never-issued");

        // expired_token, not invalid_grant: the server cannot tell a code it never minted from one it minted
        // and evicted on expiry, and answering differently would turn the endpoint into an oracle that
        // confirms which guessed codes once existed.
        await AssertRefusedAsync(response, ErrorCodes.ExpiredToken);
    }

    [Fact]
    public async Task A_device_code_cannot_be_redeemed_by_a_different_client()
    {
        // The code is issued to one client, and only that client may redeem it. Without this binding a second
        // client that observed or guessed a code in flight could complete a flow the user approved for someone
        // else, and would receive tokens carrying its own identity for a grant it was never part of.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var owner = await RegisterDeviceClientAsync(client, discovery, "code-owner");
        var stranger = await RegisterDeviceClientAsync(client, discovery, "code-stranger");

        var authorization = await StartDeviceFlowAsync(client, discovery, owner);
        var deviceCode = authorization[DeviceResponse.Parameters.DeviceCode]!.GetValue<string>();

        var response = await PollAsync(client, discovery, stranger, deviceCode);

        await AssertRefusedAsync(response, ErrorCodes.InvalidGrant);
    }

    [Fact]
    public async Task Starting_a_device_flow_requires_the_client_to_authenticate()
    {
        // Client IDs are not secrets - they travel in discovery-adjacent config and in logs. If a valid ID
        // alone were enough to mint a code pair, anyone could flood the server with user codes and phish a
        // user into approving one, and the resulting tokens would be issued under the impersonated client.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var device = await RegisterDeviceClientAsync(client, discovery, "wrong-secret");

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.DeviceAuthorizationEndpoint!,
            new Dictionary<string, string>
            {
                [DeviceRequest.Parameters.Scope] = Scopes.OpenId,
                [ClientRequest.Parameters.ClientId] = device.ClientId,
                [ClientRequest.Parameters.ClientSecret] = device.ClientSecret + "-tampered",
            });

        await AssertRefusedAsync(response, ErrorCodes.UnauthorizedClient);

        // The refusal must also produce no code pair. A rejected request that still minted a user code would
        // leave a code live on the verification page for a user to approve.
        var body = await ReadJsonAsync(response);
        Assert.Null(body[DeviceResponse.Parameters.DeviceCode]);
        Assert.Null(body[DeviceResponse.Parameters.UserCode]);
    }

    [Fact]
    public async Task A_poll_that_arrives_before_the_advertised_interval_is_throttled()
    {
        // No human gates the poll loop, so an unthrottled device is a free brute-force channel against the
        // device code and a self-inflicted load source from every idle device on a shelf. The server has to
        // enforce the interval it advertises rather than trust the client to honour it.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var device = await RegisterDeviceClientAsync(client, discovery, "fast-poller");

        var authorization = await StartDeviceFlowAsync(client, discovery, device);
        var deviceCode = authorization[DeviceResponse.Parameters.DeviceCode]!.GetValue<string>();

        // The wait the server just told this device to observe.
        Assert.True(authorization[DeviceResponse.Parameters.Interval]!.GetValue<int>() > 0);

        // The first poll is the device doing what RFC 8628 section 3.4 describes - polling as soon as it
        // holds the code - and it is answered on its merits, because the interval bounds the gap between
        // polls and there is no earlier poll for this one to be too close to.
        var first = await PollAsync(client, discovery, device, deviceCode);
        await AssertRefusedAsync(first, ErrorCodes.AuthorizationPending);

        // The second, sent immediately, is the one that ignores the interval.
        var response = await PollAsync(client, discovery, device, deviceCode);

        await AssertRefusedAsync(response, ErrorCodes.SlowDown);

        // Throttling must not become a way through: the early poll is refused without a token, exactly like
        // a well-timed poll of an unapproved code.
        var body = await ReadJsonAsync(response);
        Assert.Null(body[ResponseParameters.AccessToken]);
    }

    /// <summary>A dynamically registered client allowed to use the device authorization grant.</summary>
    private sealed record DeviceClient(string ClientId, string ClientSecret);

    /// <summary>
    /// Builds an isolated host whose polling interval is zero, so the first permitted poll falls at the moment
    /// of issuance and a test can reach the approval check without waiting out the shared host's interval. The
    /// shared default host is left untouched for the rest of the suite.
    /// </summary>
    private WebApplicationFactory<Program> CreateHostWithoutPollingDelay()
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.DeviceAuthorization!.PollingInterval = TimeSpan.Zero))));

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    /// <summary>
    /// Registers a confidential client whose only grant is the device authorization grant. None of the
    /// pre-seeded E2E clients carry it, and registering per test also gives each test an isolated identity.
    /// </summary>
    private static async Task<DeviceClient> RegisterDeviceClientAsync(
        HttpClient client, DiscoveryDocument discovery, string clientName)
    {
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationRequest.ClientName] = clientName,
            [RegistrationRequest.GrantTypes] = new JsonArray(GrantTypes.DeviceAuthorization),

            // A device client has no user agent to redirect, so it declares no response type. The MVC
            // registration model still marks redirect_uris as required, so one is supplied and never used.
            // client_secret_post keeps the credentials in the same form body the other scenarios post.
            [RegistrationRequest.ResponseTypes] = new JsonArray(),
            [RegistrationRequest.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            [RegistrationRequest.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
        });

        return new DeviceClient(
            registered[RegistrationResponse.ClientId]!.GetValue<string>(),
            registered[RegistrationResponse.ClientSecret]!.GetValue<string>());
    }

    /// <summary>
    /// Drives the device authorization endpoint and returns the parsed code pair, asserting the request
    /// succeeded so a negative test downstream cannot pass against a flow that never started.
    /// </summary>
    private static async Task<JsonObject> StartDeviceFlowAsync(
        HttpClient client, DiscoveryDocument discovery, DeviceClient device)
    {
        Assert.NotNull(discovery.DeviceAuthorizationEndpoint);

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.DeviceAuthorizationEndpoint,
            new Dictionary<string, string>
            {
                [DeviceRequest.Parameters.Scope] = Scopes.OpenId,
                [ClientRequest.Parameters.ClientId] = device.ClientId,
                [ClientRequest.Parameters.ClientSecret] = device.ClientSecret,
            });

        var body = await ReadJsonAsync(response);
        Assert.True(
            response.IsSuccessStatusCode,
            $"device authorization should succeed, got {(int)response.StatusCode}: {body}");

        // Both halves of the pair have to be there: the device polls with one and the user types the other,
        // so a response missing either leaves the flow with no way to finish.
        Assert.NotNull(body[DeviceResponse.Parameters.DeviceCode]);
        Assert.NotNull(body[DeviceResponse.Parameters.UserCode]);

        return body;
    }

    private static async Task<HttpResponseMessage> PollAsync(
        HttpClient client, DiscoveryDocument discovery, DeviceClient device, string deviceCode) =>
        await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.DeviceAuthorization,
            [TokenRequest.Parameters.DeviceCode] = deviceCode,
            [ClientRequest.Parameters.ClientId] = device.ClientId,
            [ClientRequest.Parameters.ClientSecret] = device.ClientSecret,
        });

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task AssertRefusedAsync(HttpResponseMessage response, string expectedError)
    {
        var body = await ReadJsonAsync(response);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(expectedError, body[ResponseParameters.Error]!.GetValue<string>());
    }
}
