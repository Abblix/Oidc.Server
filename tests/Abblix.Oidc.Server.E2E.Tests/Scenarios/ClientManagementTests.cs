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
using System.Reflection;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Abblix.Oidc.Server.Model;
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
    /// <summary>The JSON member every refusal in this suite reads its code out of.</summary>
    private const string ErrorMember = "error";

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
        var error = body[ErrorMember];
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, error.GetValue<string>());
    }

    /// <summary>
    /// An application type this server does not know is refused, not thrown on.
    /// </summary>
    /// <remarks>
    /// <c>[AllowedValues]</c> on the model is not enforced against a JSON body - the same gap the
    /// nullability annotation has, which this validator already carries a comment about - so an
    /// arbitrary string reaches the per-application-type switch. Its <c>default</c> used to throw, which
    /// is right for a value that cannot occur and wrong for one any caller can post: the registration
    /// left the pipeline as a server fault rather than a refusal.
    /// <para>
    /// A CIBA-only client, because that is the class the redirect-URI checks reached for the first time
    /// when they stopped being gated on the grant types - a body that answered 201 before then met the
    /// throw. Clients WITH redirect grants met it all along.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task An_unknown_application_type_is_refused_rather_than_thrown_on()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("an-application-type-nobody-defined");
        metadata[RequestMembers.GrantTypes] = new JsonArray(GrantTypes.Ciba);
        metadata[RequestMembers.ResponseTypes] = new JsonArray();
        metadata[RequestMembers.ApplicationType] = "service";

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ReadJsonAsync(response);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, body[ErrorMember]!.GetValue<string>());

        // The member by name: an operator reading "invalid_client_metadata" over a body carrying thirty
        // members has nothing to act on otherwise.
        Assert.Contains(
            RequestMembers.ApplicationType,
            body["error_description"]!.GetValue<string>(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A null ELEMENT inside a URI array is refused, not dereferenced.
    /// </summary>
    /// <remarks>
    /// A registration body is attacker-shaped JSON and the deserializer honours no annotation against an
    /// explicit null, so an array element really can be null - and a check written as
    /// <c>!uri.IsAbsoluteUri</c> reaches through it and faults the endpoint. The refusal is the answer,
    /// not a pass: unlike an absent member, a null element WAS sent, and it names nothing.
    /// </remarks>
    [Theory]
    [InlineData(RequestMembers.RedirectUris)]
    [InlineData(RequestMembers.PostLogoutRedirectUris)]
    [InlineData(RequestMembers.RequestUris)]
    public async Task A_null_element_in_a_uri_array_is_refused(string member)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata($"null-element-in-{member}");
        metadata[member] = new JsonArray((JsonNode?)null);

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// A plain-HTTP notification endpoint is refused even when no delivery mode is registered.
    /// </summary>
    /// <remarks>
    /// The arm that enforces "It MUST be an HTTPS URL" sat behind a switch whose first case returns for
    /// a null <c>backchannel_token_delivery_mode</c>, so a registration naming the endpoint and no mode
    /// walked past it and the value was stored. Measured, 201 Created. Nothing else covers it:
    /// <c>StoredUriValidator</c> asks absoluteness only, and <c>SubjectTypeValidator</c>'s arm needs a
    /// pairwise subject type.
    /// <para>
    /// Whether such a client is usable is a separate question - it has no mode, so nothing polls or
    /// pushes to it today. What is refused here is storing an address the specification forbids for the
    /// member, so that turning the mode on later cannot quietly begin using it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_plain_http_notification_endpoint_is_refused_without_a_delivery_mode()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("notified-over-plain-http");
        metadata[RequestMembers.BackChannelClientNotificationEndpoint] = "http://client.example.com/cb";

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        // The control: the same body with an https endpoint registers, so the refusal is about the
        // scheme rather than about the member being present at all.
        var accepted = await client.PostAsJsonAsync(
            registrationEndpoint,
            AsHttps(NewClientMetadata("notified-over-https")),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, accepted.StatusCode);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // And that it names the member it refused. Asserting the status alone left the one refusal this
        // change WROTE unmeasured while it hardened the naming of fourteen it did not: putting
        // redirect_uris in that message passed both suites. The whole-token form is copied from the theory
        // below so the two rows cannot drift apart - not because this member sits in a containment
        // pair, which it does not: no member name contains it and it contains none, so a plain
        // Contains would catch the same plant.
        var body = await ReadJsonAsync(response);
        var description = body["error_description"]!.GetValue<string>();
        Assert.True(
            Regex.IsMatch(
                description,
                $@"(?<!\w){Regex.Escape(RequestMembers.BackChannelClientNotificationEndpoint)}(?!\w)",
                RegexOptions.None,
                TimeSpan.FromSeconds(1)),
            $"the refusal does not name the notification endpoint: {description}");
    }

    /// <summary>
    /// The same metadata with an https notification endpoint.
    /// </summary>
    private static JsonObject AsHttps(JsonObject metadata)
    {
        metadata[RequestMembers.BackChannelClientNotificationEndpoint] = "https://client.example.com/cb";
        return metadata;
    }

    /// <summary>
    /// The registration model's URI members, found by TYPE.
    /// </summary>
    /// <remarks>
    /// A list written into a test falls behind for the same reason a list written into a validator does,
    /// and this one already did: it named eleven of fourteen. Asking the model removes the way to be
    /// wrong about which members exist.
    /// </remarks>
    public static TheoryData<string, bool> UriMembers()
    {
        var data = new TheoryData<string, bool>();

        foreach (var property in typeof(ClientRegistrationRequest)
                     .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                     .Where(p => p.PropertyType == typeof(Uri) || p.PropertyType == typeof(Uri[])))
        {
            var name = property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name ?? property.Name;
            data.Add(name, property.PropertyType == typeof(Uri[]));
        }

        return data;
    }

    /// <summary>
    /// No URI member accepts a relative value, driven through the ENDPOINT.
    /// </summary>
    /// <remarks>
    /// The half that says something reached the pipeline: <c>UriMemberCoverageTests</c> asks the
    /// validator directly and proves the list is complete, and this asks the server and proves the
    /// validator is wired. Neither replaces the other - removing the validator's DI registration leaves
    /// every unit row green.
    /// <para>
    /// Six of these members had no validator at all until the sweep that produced this row, and one was
    /// a live defect rather than an omission: a relative <c>frontchannel_logout_uri</c> registered
    /// happily and reaches <c>GetLeftPart</c> in <c>FrontChannelLogoutService</c> at logout, which
    /// raises on a relative URI.
    /// </para>
    /// </remarks>
    [Theory]
    [MemberData(nameof(UriMembers))]
    public async Task No_uri_member_accepts_a_relative_value(string member, bool isArray)
    {
        const string Relative = "/somewhere";

        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata($"relative-{member}");
        metadata[member] = isArray ? new JsonArray(Relative) : Relative;

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        // The control: the same metadata WITHOUT the member registers, so the refusal is about the value.
        var accepted = await client.PostAsJsonAsync(
            registrationEndpoint,
            NewClientMetadata($"relative-control-{member}"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, accepted.StatusCode);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // The MEMBER, not only the status. This is the only row that sees the text a client is
        // actually sent, and the validator behind it is a list of hand-written (name, value) pairs -
        // swapping two of them told an operator about the wrong member with every row still green.
        //
        // As a whole TOKEN, not a substring: redirect_uris sits inside post_logout_redirect_uris, so
        // with containment a redirect_uris refusal LABELLED post_logout_redirect_uris passed the
        // UNIT theory - and passed here too, but for an unrelated reason rather than for that one.
        // One direction only - the reverse never passed, because the longer name is not
        // contained in the shorter - and saying "for each other" would send the next reader looking
        // for a second pair that does not exist. Measured, this
        // row still cannot see that particular pair - RedirectUrisValidator is registered earlier and
        // answers a relative redirect_uris in its own words, so the mislabel never reaches the client.
        // The unit theory is what catches it, by asking the validator directly.
        var body = await ReadJsonAsync(response);
        var description = body["error_description"]!.GetValue<string>();
        Assert.True(
            Regex.IsMatch(
                description,
                $@"(?<!\w){Regex.Escape(member)}(?!\w)",
                RegexOptions.None,
                TimeSpan.FromSeconds(1)),
            $"the refusal does not name {member}: {description}");
    }

    /// <summary>
    /// No URI member accepts a host and a port with no scheme.
    /// </summary>
    /// <remarks>
    /// The detector for a whole class rather than a row for one member. A dot is legal in a URI scheme,
    /// so <c>client.example.com:8080/x</c> parses as an ABSOLUTE Uri whose Scheme is the host name and
    /// whose Host is the empty string - nothing throws, nothing is malformed, and it names no
    /// destination. A validator written with <c>IsAbsoluteUri</c> as its whole test admits it, which is
    /// how it got into this codebase once already; a validator written with the shared https predicate
    /// refuses it. This row is what makes the NEXT one fail rather than the one after that.
    /// <para>
    /// Driven through the endpoint per member, because what has to hold is that SOMETHING refuses, and
    /// which validator does is not this row's business.
    /// </para>
    /// <para>
    /// Only the members whose scheme is decided - by the fetch policy, or by the specification for a
    /// redirect URI. The rest are checked for absoluteness alone, and a host with a port IS absolute, so
    /// listing them here would assert a rule nothing in the library holds.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(RequestMembers.JwksUri, false)]
    [InlineData(RequestMembers.InitiateLoginUri, false)]
    [InlineData(RequestMembers.BackChannelLogoutUri, false)]
    [InlineData(RequestMembers.RedirectUris, true)]
    [InlineData(RequestMembers.PostLogoutRedirectUris, true)]
    public async Task No_uri_member_accepts_a_host_and_port_with_no_scheme(string member, bool isArray)
    {
        const string HostAndPort = "client.example.com:8080/callback";

        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata($"host-and-port-in-{member}");
        metadata[member] = isArray ? new JsonArray(HostAndPort) : HostAndPort;

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        // The control: the same metadata WITHOUT the member registers, so a refusal here is about the
        // value and not about a body this endpoint would have refused anyway.
        var control = NewClientMetadata($"control-for-{member}");
        var accepted = await client.PostAsJsonAsync(
            registrationEndpoint, control, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, accepted.StatusCode);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// A redirect URI is checked for shape whatever the client's grant types are.
    /// </summary>
    /// <remarks>
    /// The per-URI checks used to sit behind the same gate as the "you must register one" check, which
    /// asks whether any requested grant type NEEDS a redirect URI. A CIBA-only client needs none, so its
    /// list was stored unread: measured, <c>"redirect_uris": ["/cb"]</c> registered 201 and the value
    /// came back in the response. The two questions are different - whether a redirect URI is REQUIRED
    /// depends on the grant types, whether a registered one is VALID does not.
    /// </remarks>
    [Fact]
    public async Task A_redirect_uri_is_checked_even_for_a_client_that_needs_none()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("ciba-only-with-a-relative-callback");
        metadata[RequestMembers.GrantTypes] = new JsonArray(GrantTypes.Ciba);
        metadata[RequestMembers.ResponseTypes] = new JsonArray();
        metadata[RequestMembers.RedirectUris] = new JsonArray("/cb");

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ReadJsonAsync(response);
        var error = body[ErrorMember];
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, error.GetValue<string>());
    }

    /// <summary>
    /// A relative <c>jwks_uri</c> is refused at registration rather than stored.
    /// </summary>
    /// <remarks>
    /// RFC 7591 Section 2 makes this member a URL, and the server FETCHES it: what a relative one buys a
    /// registrant today is a client whose keys can never be loaded, so every <c>private_key_jwt</c>
    /// assertion it presents fails as "no signing key matched" - a message that names neither the client
    /// metadata nor the moment the mistake was made. It cannot fault at fetch time either: an absent
    /// base address makes the HTTP client refuse the request before the outbound policy handler runs, and
    /// the fetcher catches everything and answers with an empty key set. Refusing it here is the only
    /// place the registrant is still on the line to be told.
    /// <para>
    /// Driven through the endpoint rather than against the validator alone, because the gap this closes
    /// was a validator that existed and was never REACHED - a unit row over the same class would have
    /// passed the whole time it was open.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_relative_jwks_uri_is_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var metadata = NewClientMetadata("keys-from-nowhere");
        metadata[RequestMembers.JwksUri] = "/.well-known/jwks.json";

        var registrationEndpoint = discovery.RegistrationEndpoint;
        Assert.NotNull(registrationEndpoint);

        var response = await client.PostAsJsonAsync(
            registrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ReadJsonAsync(response);
        var error = body[ErrorMember];
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.GetValue<string>());

        // The MEMBER, not just the code: twenty-odd validators answer invalid_client_metadata, so the
        // code alone stays green when some other one refuses for some other reason, and what proves this
        // validator ran would live only in a mutation outside the suite.
        var description = body["error_description"];
        Assert.NotNull(description);
        Assert.Contains(
            RequestMembers.JwksUri, description.GetValue<string>(), StringComparison.Ordinal);
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
