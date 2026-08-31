// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
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

    [Fact]
    public async Task A_push_client_is_delivered_its_tokens_at_the_notification_endpoint()
    {
        // Push is the one mode whose delivery path is entirely different: the tokens are minted when the
        // host completes and posted to the client, which never comes to the token endpoint at all. Nothing
        // outside unit tests watched that path, so a token that is minted and not delivered - or delivered
        // to the wrong place, or without the token that proves the notification came from here - looked the
        // same as success.
        var deliveries = new NotificationRecorder();
        await using var host = CreateCibaHost(deliveries);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterPushCibaClientAsync(client, discovery);

        var authRequestId = await InitiateAsync(client, discovery, ciba, RequestedDetails, NotificationToken);
        await CompleteAsync(host, authRequestId, RequestedDetails);

        var delivery = Assert.Single(deliveries.Received);
        Assert.Equal(NotificationEndpoint, delivery.Endpoint);

        // The notification token is what tells the client this POST is the answer to its own request rather
        // than an unsolicited one, so a delivery carrying the tokens without it is not a delivery. The
        // scheme is asserted beside it because CIBA Core 1.0 section 10.3.1 names Bearer, and a token in
        // the right header under the wrong scheme is what a client's own middleware would reject.
        Assert.Equal("Bearer", delivery.AuthorizationScheme);
        Assert.Equal(NotificationToken, delivery.BearerToken);

        // Every member the client is issued, not just the one that proves something arrived. Each of these
        // can be dropped from the payload on its own, and an assertion only on access_token sees none of it.
        var payload = delivery.Payload;
        Assert.Equal(authRequestId, payload["auth_req_id"]!.GetValue<string>());
        Assert.False(string.IsNullOrEmpty(payload["access_token"]?.GetValue<string>()));
        Assert.False(string.IsNullOrEmpty(payload["id_token"]?.GetValue<string>()));
        Assert.Equal(TokenTypes.Bearer, payload["token_type"]!.GetValue<string>());
        Assert.True(payload["expires_in"]!.GetValue<int>() > 0);

        // And the request is gone. That removal is this library's choice rather than a requirement -
        // CIBA Core 1.0 section 10.3.1 says nothing about what the OP keeps - and the reason is that push
        // never writes back: a record left behind is the PRE-completion one, which a host can complete
        // again, delivering what the end user did not approve.
        //
        // Both arms of the delivery branch are already pinned by AuthenticationCompletionHandlerTests,
        // through a mock's call count. What this line adds is the same fact at the level a client sees,
        // which is the level where a removal that stops happening actually costs something. It does not
        // pin the branch: hoisting the removal above the if, so it runs whether or not delivery
        // succeeded, leaves every test in this file green and only the unit test red.
        using var scope = host.Services.CreateScope();
        var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();
        Assert.Null(await storage.TryGetAsync(authRequestId));
    }

    [Fact]
    public async Task The_narrowing_a_host_performs_at_completion_reaches_the_pushed_token()
    {
        // A push client cannot be asked to check what it was granted - it never redeems anything, it just
        // receives a token. So an end user who approved one of two entries is only honoured if the
        // narrowing survives every step between the completion call and the bytes on the wire. Asserting
        // it in storage would prove the host wrote it down, which is the half that was never in doubt.
        var deliveries = new NotificationRecorder();
        await using var host = CreateCibaHost(deliveries);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterPushCibaClientAsync(client, discovery);

        var authRequestId = await InitiateAsync(client, discovery, ciba, BothDetails, NotificationToken);
        await CompleteAsync(host, authRequestId, ApprovedDetail);

        var delivered = Assert.Single(deliveries.Received);
        var granted = ReadAuthorizationDetails(delivered.Payload["access_token"]!.GetValue<string>());

        var entry = Assert.Single(granted);
        Assert.Equal(TestConstants.PaymentInitiationType, entry!["type"]!.GetValue<string>());

        // The action is what separates the two entries, so it is what proves the refused one was dropped
        // rather than that the array merely came out the right length.
        Assert.Equal("status", entry["actions"]![0]!.GetValue<string>());
    }

    [Fact]
    public async Task A_push_grant_the_per_type_validator_refuses_delivers_nothing()
    {
        // The per-type gate for push exists because a push client is never judged at the token endpoint,
        // where the other two modes are. A gate that refuses and delivers anyway, or that lets a grant the
        // validator rejected through, is invisible to a unit test whose fixture could not be delivered to
        // in the first place. Here a token either arrives or it does not.
        //
        // The narrowing is one a host got WRONG rather than a malicious one: the entry keeps the type it
        // asked for and loses the amount, which is the shape the type comparison structurally cannot see
        // and the reason the per-type validator is asked at all.
        var deliveries = new NotificationRecorder();
        await using var host = CreateCibaHost(deliveries);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterPushCibaClientAsync(client, discovery);

        var authRequestId = await InitiateAsync(client, discovery, ciba, RequestedDetails, NotificationToken);

        // What the request ASKED for has to be on it. With nothing requested, the type comparison one
        // step earlier refuses first, removes the request and delivers nothing - the identical observable
        // state, reached without the per-type validator ever being asked, and this rules that out.
        //
        // It rules out only that. The same comparison also refuses a granted type absent from a non-empty
        // baseline, and no assertion here separates the two refusals: they differ in the log line and in
        // nothing a client can see. The narrowing below keeps the type it asked for, so the comparison
        // has no reason to fire - but that is an argument, not a measurement.
        await AssertTheRequestCarriesWhatWasAskedFor(host, authRequestId);

        await CompleteAsync(host, authRequestId, DetailWithoutAmount);

        Assert.Empty(deliveries.Received);

        // And the request does not sit there afterwards. A push client never polls, so a refused request
        // left in storage is an orphan nobody reads until it expires.
        using var scope = host.Services.CreateScope();
        var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();
        Assert.Null(await storage.TryGetAsync(authRequestId));
    }

    /// <summary>The identifier the client passes to name the end-user to be contacted.</summary>
    private const string LoginHint = "e2e-subject";

    /// <summary>
    /// Where a push client is told to deliver. Absolute and https because dynamic registration requires it;
    /// nothing resolves this name, since the recorder below stands in for the transport.
    /// </summary>
    private static readonly Uri NotificationEndpoint = new("https://client.e2e.invalid/ciba-push");

    /// <summary>The value the client sends at initiation and expects back on the notification.</summary>
    private const string NotificationToken = "e2e-client-notification-token";

    private const string RequestedDetails =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    private const string BothDetails =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}},{"type":"payment_initiation","actions":["status"],"instructedAmount":{"currency":"EUR","amount":"10.00"}}]""";

    /// <summary>The second of <see cref="BothDetails"/> alone: the end user approved the cheaper one.</summary>
    private const string ApprovedDetail =
        """[{"type":"payment_initiation","actions":["status"],"instructedAmount":{"currency":"EUR","amount":"10.00"}}]""";

    /// <summary>
    /// A narrowing of <see cref="RequestedDetails"/> that keeps the type and drops the amount, which is what
    /// <c>PaymentInitiationValidator</c> refuses.
    /// </summary>
    private const string DetailWithoutAmount =
        """[{"type":"payment_initiation","actions":["initiate"]}]""";

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
    private static Task<string> InitiateAsync(
        HttpClient client, DiscoveryDocument discovery, CibaClient ciba)
        => InitiateAsync(client, discovery, ciba, authorizationDetails: null, notificationToken: null);

    /// <summary>
    /// Starts a backchannel authentication carrying authorization_details and the notification token a push
    /// client must present back, asserting acceptance so a later assertion cannot pass against a flow that
    /// never started.
    /// </summary>
    private static async Task<string> InitiateAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        CibaClient ciba,
        string? authorizationDetails,
        string? notificationToken)
    {
        var form = new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.BindingMessage] = "e2e-binding",
                [ClientRequest.Parameters.ClientId] = ciba.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
            };

        // Omitted rather than sent empty, because that is what a client that wants neither actually
        // sends. The server does not distinguish the two - the processor stores an empty array either
        // way - but a request the poll tests share should not carry parameters they never used.
        if (notificationToken is not null)
            form[CibaParameters.ClientNotificationToken] = notificationToken;

        if (authorizationDetails is not null)
            form[CibaParameters.AuthorizationDetails] = authorizationDetails;

        var response = await FormPostHelpers.PostFormAsync(
            client, discovery.BackChannelAuthenticationEndpoint!, form);

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

    /// <summary>
    /// Builds the CIBA host with the notification transport pointed at <paramref name="recorder"/>, so what
    /// the server posts to a push client can be read back.
    /// </summary>
    /// <remarks>
    /// The recorder replaces the client's PRIMARY handler. That is where the address validation of a
    /// client-supplied endpoint lives, together with the transport it wraps - which also refuses
    /// redirects, default credentials and automatic decompression. So these tests say nothing about any
    /// of that, and the endpoint they register is never resolved. Chaining an outer handler instead
    /// would leave the validation standing in front of an address no test host can own.
    /// </remarks>
    private WebApplicationFactory<Program> CreateCibaHost(NotificationRecorder recorder)
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.Replace(ServiceDescriptor
                    .Scoped<IUserDeviceAuthenticationHandler, ReachableUserDeviceHandler>());

                services
                    .AddHttpClient(BackChannelNotificationTransport.HttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => recorder);
            }));

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    /// <summary>
    /// Registers a CIBA client in PUSH mode, with the notification endpoint the recorder captures POSTs
    /// to and the authorization-detail type the host has a validator for.
    /// </summary>
    private static async Task<CibaClient> RegisterPushCibaClientAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.ClientName] = $"ciba-push-{Guid.NewGuid():N}",
            [RegistrationMembers.ResponseTypes] = new JsonArray(),
            [RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.Ciba),
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.BackChannelTokenDeliveryMode] = BackchannelTokenDeliveryModes.Push,
            [RegistrationMembers.BackChannelClientNotificationEndpoint] = NotificationEndpoint.AbsoluteUri,
            [RegistrationMembers.AuthorizationDetailsTypes] =
                new JsonArray(TestConstants.PaymentInitiationType),
        });

        return new CibaClient(
            registered[RegistrationResponse.ClientId]!.GetValue<string>(),
            registered[RegistrationResponse.ClientSecret]!.GetValue<string>());
    }

    /// <summary>
    /// Reads back what the request ASKED for, which rules out one of the two ways the comparison that runs
    /// before the per-type validator can refuse: an empty requested baseline.
    /// </summary>
    private static async Task AssertTheRequestCarriesWhatWasAskedFor(
        WebApplicationFactory<Program> host, string authenticationRequestId)
    {
        using var scope = host.Services.CreateScope();
        var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();

        var stored = await storage.TryGetAsync(authenticationRequestId);
        Assert.NotNull(stored);
        Assert.NotEmpty(stored.RequestedAuthorizationDetails ?? []);
    }

    /// <summary>
    /// Does what an integrator does when the end user answers on their device: reads the stored request,
    /// puts the session and the grant the user actually approved on it, marks it authenticated and hands it
    /// to the completion handler. Nothing in the library drives this - the answer arrives from outside.
    /// </summary>
    /// <param name="host">The running test host, whose service provider owns the request storage.</param>
    /// <param name="authenticationRequestId">Identifies the stored request the answer belongs to.</param>
    /// <param name="grantedDetails">
    /// The authorization_details the end user approved, which is how a partial answer is expressed: the
    /// grant's context is what will be issued, and replacing it is the only place that answer exists.
    /// </param>
    private static async Task CompleteAsync(
        WebApplicationFactory<Program> host, string authenticationRequestId, string grantedDetails)
    {
        using var scope = host.Services.CreateScope();
        var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();

        var stored = await storage.TryGetAsync(authenticationRequestId);
        Assert.NotNull(stored);

        var session = new AuthSession(
            Subject: LoginHint,
            SessionId: Guid.NewGuid().ToString("N"),
            AuthenticationTime: scope.ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow(),
            IdentityProvider: "e2e-test");

        var granted = stored.AuthorizedGrant.Context with
        {
            AuthorizationDetails = JsonNode.Parse(grantedDetails)!.AsArray(),
        };

        var completed = stored with { AuthorizedGrant = new AuthorizedGrant(session, granted) };
        completed.Status = BackChannelAuthenticationStatus.Authenticated;

        await scope.ServiceProvider
            .GetRequiredService<IAuthenticationCompletionHandler>()
            .CompleteAsync(authenticationRequestId, completed, TimeSpan.FromMinutes(5));
    }

    private static JsonArray ReadAuthorizationDetails(string accessToken)
        => DecodeJwtPayload(accessToken)[IanaClaimTypes.AuthorizationDetails]!.AsArray();

    /// <summary>What the server posted to a push or ping client's notification endpoint.</summary>
    private sealed record RecordedNotification(
        Uri Endpoint, string? AuthorizationScheme, string? BearerToken, JsonObject Payload);

    /// <summary>
    /// Stands in for the client's notification endpoint. It answers 200 to every POST and keeps what
    /// arrived, which is the whole point: a push client's tokens exist nowhere else once delivery succeeds.
    /// </summary>
    private sealed class NotificationRecorder : HttpMessageHandler
    {
        private readonly List<RecordedNotification> _received = [];

        public IReadOnlyList<RecordedNotification> Received
        {
            get
            {
                lock (_received) return _received.ToArray();
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? new JsonObject()
                : JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();

            lock (_received)
            {
                _received.Add(new RecordedNotification(
                    request.RequestUri!,
                    request.Headers.Authorization?.Scheme,
                    request.Headers.Authorization?.Parameter,
                    body));
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

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
