// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the client configuration endpoint of RFC 7592: reading, updating and deleting a
/// registration with the registration access token issued alongside it.
/// </summary>
/// <remarks>
/// The suite registered clients thirteen times over and never read, changed or deleted one afterwards, so the
/// half of dynamic registration that is an authenticated management API over other people's clients went
/// unexercised.
///
/// The property that matters here is not the response shape but who is allowed through. A registration access
/// token is bound to one client, and a server that accepts one client's token against another's registration
/// lets any registrant read a competitor's secret, point its redirect URIs at an attacker, or delete it
/// outright. Every test below is written around that boundary rather than around the formatter behind it.
/// </remarks>
public class ClientManagementTests(TestFactory factory) : TestBase(factory)
{
    // Named once: the same member is written into a request and looked for in a response and in an
    // extension's view, and those three have to agree.
    private const string VendorTier = "x_vendor_tier";

    // The member every size test pads with: named once so the boundary cases and the oversized cases
    // measure the same document rather than two that happen to look alike.
    private const string VendorPad = "x_vendor_blob";

    private static JsonObject NewClientMetadata(string clientName) => new()
    {
        [RequestMembers.ClientName] = clientName,
        [RequestMembers.RedirectUris] = new JsonArray("https://client.example.com/callback"),
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
        [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
    };

    private sealed record Registration(string ClientId, string AccessToken, Uri ConfigurationUri);

    private static async Task<Registration> RegisterAsync(
        HttpClient client, DiscoveryDocument discovery, string clientName)
    {
        var registered = await RegisterClientAsync(client, discovery, NewClientMetadata(clientName));

        return new Registration(
            registered[ResponseMembers.ClientId]!.GetValue<string>(),
            registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>(),
            new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>(), UriKind.RelativeOrAbsolute));
    }

    private static HttpRequestMessage Request(HttpMethod method, Uri uri, string? accessToken)
    {
        var request = new HttpRequestMessage(method, uri);
        if (accessToken is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        return request;
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    /// <summary>
    /// A client whose grants redirect still has to register a redirect URI, and is told so in the
    /// protocol's own terms.
    /// </summary>
    /// <remarks>
    /// The requirement lives in the validator that expresses it correctly - it applies when the requested
    /// grants include one that redirects - rather than as a declarative constraint on the model, which ran
    /// first and refused a device-flow or CIBA client that has no user agent to redirect. This case is the
    /// other half of that change: the rule is still enforced where it applies, and the refusal carries
    /// invalid_redirect_uri rather than a transport-level complaint naming a C# property.
    /// </remarks>
    [Fact]
    public async Task A_redirecting_client_still_has_to_register_a_redirect_uri()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // The metadata every other case here registers with, minus the one member under test - so what
        // differs between an accepted registration and this one is exactly the redirect URI.
        var metadata = NewClientMetadata("redirecting-without-a-uri");
        metadata.Remove(RequestMembers.RedirectUris);

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ReadJsonAsync(response);
        var error = body["error"];
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, error.GetValue<string>());
    }

    /// <summary>
    /// The registration response carries only what this server knows. A member the core does not model is
    /// kept for an extension to read, and keeping it must not turn the endpoint into a mirror for whatever
    /// JSON a stranger posts at it.
    /// </summary>
    [Fact]
    public async Task An_unmodelled_member_is_not_echoed_in_the_response()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("keeps-its-own-metadata");
        metadata[VendorTier] = "gold";

        var registered = await RegisterClientAsync(client, discovery, metadata);

        Assert.NotNull(registered[ResponseMembers.ClientId]);

        // The response is built from a separate type, so nothing the caller sent comes back by accident.
        // Asserted rather than assumed: the day someone builds the response from the request, this says so.
        Assert.Null(registered[VendorTier]);
    }

    /// <summary>
    /// Records what an extension sees of a registration, which is the only vantage point from which "the
    /// member survived" can be asserted: the response deliberately does not carry it, so a test reading the
    /// response alone cannot tell a kept member from a discarded one.
    /// </summary>
    private sealed class CapturingValidator : IClientRegistrationContextValidator
    {
        public IDictionary<string, JsonElement>? Seen { get; private set; }

        public Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
        {
            Seen = context.Request.AdditionalMembers;
            return Task.FromResult<OidcError?>(null);
        }
    }

    /// <summary>
    /// A member the core does not model reaches an extension point intact, name and value. Remove the
    /// extension data from the request model and the information is gone before anything a host registered
    /// can run.
    /// </summary>
    /// <remarks>
    /// The capturing validator joins the family through <c>Decompose().AddLast</c>, which is also half of
    /// what this test proves. Registering the contract directly would replace the composed pipeline instead
    /// of extending it, and the test would then pass over a host with no registration validation at all -
    /// which is why it also asserts, in the same host, that an invalid registration is still refused.
    /// </remarks>
    [Fact]
    public async Task An_unmodelled_member_reaches_an_extension_point()
    {
        var capturing = new CapturingValidator();
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Decompose<IClientRegistrationContextValidator>()
                    .AddLast(ServiceDescriptor.Singleton<IClientRegistrationContextValidator>(capturing))));

        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("seen-by-an-extension");
        metadata[VendorTier] = "gold";

        await RegisterClientAsync(client, discovery, metadata);

        Assert.NotNull(capturing.Seen);
        Assert.True(capturing.Seen.TryGetValue(VendorTier, out var tier));
        Assert.Equal("gold", tier.GetString());

        // Only the unmodelled member is here: everything the core models was parsed into its own property,
        // and finding one of those here would mean the mapping had stopped working.
        Assert.Equal([VendorTier], capturing.Seen.Keys);

        // The pipeline this validator joined is still whole. Without this the test would stay green over a
        // host that validates nothing, and the added validator is exactly what could have caused that.
        var invalid = NewClientMetadata("no-redirect-uri");
        invalid.Remove(RequestMembers.RedirectUris);
        var refusal = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint, invalid, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, refusal.StatusCode);
    }

    /// <summary>
    /// Members the core does not model never cause a refusal, however many of them arrive. RFC 7591
    /// Section 2 requires the server to ignore metadata it does not understand, and OpenID Connect Dynamic
    /// Client Registration 1.0 Section 3.2 states the same rule, so a count-based refusal would be a
    /// refusal for exactly that reason.
    /// </summary>
    [Fact]
    public async Task Many_unmodelled_members_are_ignored_rather_than_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("brings-a-lot");
        for (var i = 0; i < 256; i++)
            metadata[$"x_vendor_member_{i}"] = "value";

        var registered = await RegisterClientAsync(client, discovery, metadata);

        Assert.NotNull(registered[ResponseMembers.ClientId]);
    }

    /// <summary>
    /// An oversized body is refused before it is bound. This is the only place a bound can work: model
    /// binding materializes the unmodelled members ahead of every validator, so a bound
    /// expressed as a validator would be paid for after the allocation it exists to prevent.
    /// </summary>
    [Fact]
    public async Task An_oversized_registration_body_is_refused_before_it_is_parsed()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("brings-too-much");
        metadata[VendorPad] = new string('a', 256 * 1024);

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    /// <summary>
    /// The boundary itself, from both sides, over a body that declares no length - which is the case that
    /// forces the server to measure rather than believe what it was told.
    /// </summary>
    /// <remarks>
    /// Written as one theory over an overshoot of zero and one because the two cases are the same document
    /// differing by a single byte: anything wider leaves the comparison free to drift by one in either
    /// direction with every test still green, and the accepted side is the half that would drift silently.
    /// </remarks>
    [Theory]
    [InlineData(0, HttpStatusCode.Created)]
    [InlineData(1, HttpStatusCode.RequestEntityTooLarge)]
    public async Task A_body_at_the_boundary_is_decided_by_one_byte(int overshoot, HttpStatusCode expected)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var limit = Factory.Services.GetRequiredService<IOptions<OidcOptions>>()
            .Value.MaxRegistrationRequestSize;
        Assert.NotNull(limit);

        var clientName = $"at-the-boundary-{overshoot}";

        // Everything the document costs apart from the padding, measured rather than counted by hand: the
        // point of the test is a single byte, so an assumption about the framing would decide the outcome.
        var probe = NewClientMetadata(clientName);
        probe[VendorPad] = string.Empty;
        var framing = Encoding.UTF8.GetByteCount(probe.ToJsonString());

        var metadata = NewClientMetadata(clientName);
        metadata[VendorPad] = new string('a', (int)(limit.Value - framing) + overshoot);

        var body = metadata.ToJsonString();
        Assert.Equal(limit.Value + overshoot, Encoding.UTF8.GetByteCount(body));

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.RegistrationEndpoint)
        {
            Content = new StringContent(body, Encoding.UTF8, MediaTypeNames.Application.Json),
        };

        // Chunked on purpose: a declared length is settled without reading, so it would exercise a
        // different comparison than the one this test is about.
        request.Content.Headers.ContentLength = null;
        request.Headers.TransferEncodingChunked = true;

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(expected, response.StatusCode);
    }

    /// <summary>
    /// The update endpoint carries the same bound. It binds the same model, and it does so ahead of the
    /// registration access token check, so an unbounded one would leave the hole next door to the fix.
    /// </summary>
    [Fact]
    public async Task An_oversized_update_body_is_refused_before_it_is_bound()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery, "updates-too-much");

        var metadata = NewClientMetadata("updates-too-much");
        metadata[RequestMembers.ClientId] = registration.ClientId;
        metadata[VendorPad] = new string('a', 256 * 1024);

        using var request = Request(HttpMethod.Put, registration.ConfigurationUri, registration.AccessToken);
        request.Content = JsonContent.Create(metadata);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task A_client_can_read_its_own_registration()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery, "reader");

        var response = await client.SendAsync(
            Request(HttpMethod.Get, registration.ConfigurationUri, registration.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await ReadJsonAsync(response);
        Assert.Equal(registration.ClientId, body[ResponseMembers.ClientId]!.GetValue<string>());
    }

    [Fact]
    public async Task One_clients_token_does_not_open_anothers_registration()
    {
        // The boundary this endpoint exists to hold. Both clients registered through the same open endpoint,
        // so an attacker is simply someone who registered - if the token were not bound to its own client,
        // registering once would grant read and write over every other registration on the server.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var victim = await RegisterAsync(client, discovery, "victim");
        var attacker = await RegisterAsync(client, discovery, "attacker");

        var response = await client.SendAsync(
            Request(HttpMethod.Get, victim.ConfigurationUri, attacker.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"another client's token must not read this registration, got {(int)response.StatusCode}");
    }

    [Fact]
    public async Task A_registration_cannot_be_read_without_a_token()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery, "unauthenticated-read");

        var response = await client.SendAsync(
            Request(HttpMethod.Get, registration.ConfigurationUri, accessToken: null),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_update_changes_what_a_later_read_returns()
    {
        // Asserting the update through a fresh read rather than through its own response: a handler that
        // echoed the submitted metadata without storing it would satisfy the response assertion and change
        // nothing at all.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery, "before-update");

        var updated = NewClientMetadata("after-update");
        updated[RequestMembers.ClientId] = registration.ClientId;

        var update = Request(HttpMethod.Put, registration.ConfigurationUri, registration.AccessToken);
        update.Content = JsonContent.Create(updated);
        var updateResponse = await client.SendAsync(update, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);

        // RFC 7592 lets the server hand back a fresh registration access token, and this one does. Reading
        // with the token from registration would then fail, so the response is the authority on which token
        // is current - a client that keeps using the old one locks itself out of its own registration.
        var updateBody = await ReadJsonAsync(updateResponse);
        var currentToken = updateBody[ResponseMembers.RegistrationAccessToken]?.GetValue<string>()
                           ?? registration.AccessToken;

        var read = await client.SendAsync(
            Request(HttpMethod.Get, registration.ConfigurationUri, currentToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        Assert.Equal("after-update", (await ReadJsonAsync(read))[RequestMembers.ClientName]!.GetValue<string>());
    }

    [Fact]
    public async Task An_update_rotates_the_registration_access_token()
    {
        // RFC 7592 Section 2.2 permits a fresh token in the update response, and this server issues one. That
        // is worth pinning rather than leaving as an accident of implementation: the token from registration
        // stops working the moment a client updates itself, so a client that ignores the response body locks
        // itself out of its own registration, and the failure appears only on the next management call.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery, "rotating");

        var updated = NewClientMetadata("rotating");
        updated[RequestMembers.ClientId] = registration.ClientId;

        var update = Request(HttpMethod.Put, registration.ConfigurationUri, registration.AccessToken);
        update.Content = JsonContent.Create(updated);
        var updateBody = await ReadJsonAsync(
            await client.SendAsync(update, TestContext.Current.CancellationToken));

        var rotated = updateBody[ResponseMembers.RegistrationAccessToken]!.GetValue<string>();
        Assert.NotEqual(registration.AccessToken, rotated);

        var withSupersededToken = await client.SendAsync(
            Request(HttpMethod.Get, registration.ConfigurationUri, registration.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.NotEqual(HttpStatusCode.OK, withSupersededToken.StatusCode);
    }

    [Fact]
    public async Task One_clients_token_cannot_rewrite_anothers_registration()
    {
        // The write side of the same boundary, and the more damaging one: a redirect URI is where the
        // authorization code is delivered, so rewriting another client's registration redirects its sign-ins.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var victim = await RegisterAsync(client, discovery, "write-victim");
        var attacker = await RegisterAsync(client, discovery, "write-attacker");

        var hijacked = NewClientMetadata("write-victim");
        hijacked[RequestMembers.ClientId] = victim.ClientId;
        hijacked[RequestMembers.RedirectUris] = new JsonArray("https://attacker.example.com/callback");

        var update = Request(HttpMethod.Put, victim.ConfigurationUri, attacker.AccessToken);
        update.Content = JsonContent.Create(hijacked);
        var response = await client.SendAsync(update, TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"another client's token must not rewrite this registration, got {(int)response.StatusCode}");

        // And it really did not take effect, which is the half a status code alone does not prove.
        var read = await client.SendAsync(
            Request(HttpMethod.Get, victim.ConfigurationUri, victim.AccessToken),
            TestContext.Current.CancellationToken);

        var redirectUris = (await ReadJsonAsync(read))[RequestMembers.RedirectUris]!.AsArray();
        Assert.DoesNotContain(
            redirectUris,
            uri => uri!.GetValue<string>().Contains("attacker.example.com", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_deleted_registration_is_gone_and_its_token_stops_working()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery, "to-be-deleted");

        var deletion = await client.SendAsync(
            Request(HttpMethod.Delete, registration.ConfigurationUri, registration.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, deletion.StatusCode);

        // Deleting a client that still answers reads afterwards would leave its secret retrievable by whoever
        // holds the token, which is exactly what deletion is asked for after a compromise.
        var readAfterDeletion = await client.SendAsync(
            Request(HttpMethod.Get, registration.ConfigurationUri, registration.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.NotEqual(HttpStatusCode.OK, readAfterDeletion.StatusCode);
    }

    [Fact]
    public async Task One_clients_token_cannot_delete_anothers_registration()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var victim = await RegisterAsync(client, discovery, "delete-victim");
        var attacker = await RegisterAsync(client, discovery, "delete-attacker");

        var response = await client.SendAsync(
            Request(HttpMethod.Delete, victim.ConfigurationUri, attacker.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"another client's token must not delete this registration, got {(int)response.StatusCode}");

        var stillThere = await client.SendAsync(
            Request(HttpMethod.Get, victim.ConfigurationUri, victim.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, stillThere.StatusCode);
    }
}
