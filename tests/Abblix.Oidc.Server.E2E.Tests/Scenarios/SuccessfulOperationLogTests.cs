// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Trace;
using Xunit;
using RegistrationRequest = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using RegistrationResponse = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A running server records each successful security-relevant operation through the host's own logging, at
/// Information under a stable event id: who was handed which tokens, and which clients it came to serve. The subject is
/// named only by its fingerprint, and no token value reaches a record.
/// </summary>
public sealed class SuccessfulOperationLogTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// The event ids an operator alerts on, as the server publishes them: they are the contract, and a renumbering is
    /// a change this test refuses.
    /// </summary>
    private static class EventIds
    {
        public const int TokensIssued = 11120;
        public const int FrontChannelTokensIssued = 11121;
        public const int ClientRegistered = 10680;
        public const int ClientUpdated = 10681;
        public const int ClientRemoved = 10682;
    }

    private const string Subject = "e2e-subject";

    private readonly ActivityTraceId _trace = ActivityTraceId.CreateRandom();

    private (WebApplicationFactory<Program> Host, OwnTraceEvents Events, OwnTraceSpans Spans) CreateHost(
        Action<IServiceCollection>? configure = null)
    {
        var events = new OwnTraceEvents(_trace);
        var spans = new OwnTraceSpans(_trace);
        var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            configure?.Invoke(services);
            services.AddOpenTelemetry()
                .WithTracing(tracing => tracing.AddSource(OidcTelemetry.SourceName).AddProcessor(spans))
                .WithLogging(logging => logging.AddProcessor(events));
        }));
        return (host, events, spans);
    }

    private HttpClient CreateClientFor(WebApplicationFactory<Program> host)
    {
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        // Every request of the test carries one trace, so the records of tests running alongside are told apart
        client.DefaultRequestHeaders.Add("traceparent", $"00-{_trace}-{ActivitySpanId.CreateRandom()}-01");
        return client;
    }

    [Fact]
    public async Task Tokens_issued_at_the_token_endpoint_are_recorded_for_each_grant()
    {
        var (host, events, spans) = CreateHost();
        await using var _ = host;
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshed = await ReadJsonAsync(await RefreshAsync(
            client, discovery, tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>()));
        var machine = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var issued = events.Of(EventIds.TokensIssued);
        Assert.Equal(
            new[] { GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials, GrantTypes.RefreshToken },
            issued.Select(record => record.Attributes["GrantType"]).Order());
        Assert.All(issued, record => Assert.Equal(LogLevel.Information, record.Level));

        var code = Assert.Single(issued, record => record.Attributes["GrantType"] == GrantTypes.AuthorizationCode);
        Assert.Equal(TestTenantSettings.TenantId, code.Attributes["TenantId"]);
        Assert.Equal(TestConstants.ConfidentialClientId, code.Attributes["ClientId"]);
        Assert.Equal(Fingerprint(host, Subject), code.Attributes["Subject"]);
        Assert.Equal(
            new[] { TelemetryTokenTypes.AccessToken, TelemetryTokenTypes.IdToken, TelemetryTokenTypes.RefreshToken },
            code.Attributes["Tokens"]!.Split(' ').Order());
        Assert.Contains(Scopes.OpenId, code.Attributes["Scope"]!.Split(' '));

        // The refresh continues the family the code founded, and the record says which
        var refresh = Assert.Single(issued, record => record.Attributes["GrantType"] == GrantTypes.RefreshToken);
        Assert.False(string.IsNullOrEmpty(code.Attributes["GrantId"]));
        Assert.Equal(code.Attributes["GrantId"], refresh.Attributes["GrantId"]);

        var credentials = Assert.Single(issued, record => record.Attributes["GrantType"] == GrantTypes.ClientCredentials);
        Assert.Equal(TestConstants.ClientCredentialsClientId, credentials.Attributes["ClientId"]);

        AssertNoSecretReached(events, Subject, tokens, refreshed, machine);

        // The token endpoint's span names the client the request authenticated
        Assert.Contains(
            spans.Spans,
            span => Equals(span.GetTagItem(TelemetryTags.Endpoint), TelemetryEndpoints.Token) &&
                    Equals(span.GetTagItem(TelemetryTags.ClientId), TestConstants.ClientCredentialsClientId));
    }

    [Fact]
    public async Task Tokens_handed_out_through_the_front_channel_are_recorded_and_a_code_alone_is_not()
    {
        var (host, events, _) = CreateHost(services => services.EnableImplicitFlow());
        await using var __ = host;
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationRequest.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            [RegistrationRequest.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.Implicit),
            [RegistrationRequest.ResponseTypes] = new JsonArray("code id_token"),
            [RegistrationRequest.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
        });
        var clientId = registered[RegistrationResponse.ClientId]!.GetValue<string>();

        var parameters = CodeFlowParameters(clientId, GeneratePkcePair().Challenge);
        parameters[AuthorizationRequest.Parameters.ResponseType] = "code id_token";
        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters), TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther, $"{(int)response.StatusCode}");
        var callback = System.Web.HttpUtility.ParseQueryString(response.Headers.Location!.Fragment.TrimStart('#'));
        var idToken = callback[ResponseParameters.IdToken];
        Assert.False(string.IsNullOrEmpty(idToken));

        var issued = Assert.Single(events.Of(EventIds.FrontChannelTokensIssued));
        Assert.Equal(LogLevel.Information, issued.Level);
        Assert.Equal(clientId, issued.Attributes["ClientId"]);
        Assert.Equal(TelemetryTokenTypes.IdToken, issued.Attributes["Tokens"]);
        Assert.Equal(GrantTypes.Implicit, issued.Attributes["GrantType"]);
        Assert.Equal(Fingerprint(host, Subject), issued.Attributes["Subject"]);
        Assert.DoesNotContain(events.Events.SelectMany(record => record.Attributes.Values), value => value == idToken);

        // A code is recorded where it is redeemed, never where it is handed out
        await AuthorizeAndExtractCodeAsync(
            client, discovery, CodeFlowParameters(TestConstants.ConfidentialClientId, GeneratePkcePair().Challenge));
        Assert.Single(events.Of(EventIds.FrontChannelTokensIssued));
    }

    [Fact]
    public async Task A_client_registered_updated_and_removed_is_recorded_at_each_step()
    {
        var (host, events, spans) = CreateHost();
        await using var _ = host;
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = new JsonObject
        {
            [RegistrationRequest.ClientName] = "recorded",
            [RegistrationRequest.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            [RegistrationRequest.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
            [RegistrationRequest.ResponseTypes] = new JsonArray(ResponseTypes.Code),
        };
        var registered = await RegisterClientAsync(client, discovery, metadata);
        var clientId = registered[RegistrationResponse.ClientId]!.GetValue<string>();
        var configuration = new Uri(
            registered[RegistrationResponse.RegistrationClientUri]!.GetValue<string>(), UriKind.RelativeOrAbsolute);

        var recorded = Assert.Single(events.Of(EventIds.ClientRegistered));
        Assert.Equal(LogLevel.Information, recorded.Level);
        Assert.Equal(TestTenantSettings.TenantId, recorded.Attributes["TenantId"]);
        Assert.Equal(clientId, recorded.Attributes["ClientId"]);
        Assert.Equal(GrantTypes.AuthorizationCode, recorded.Attributes["GrantTypes"]);

        metadata[RegistrationRequest.ClientId] = clientId;
        using var update = Authorized(HttpMethod.Put, configuration, registered);
        update.Content = JsonContent.Create(metadata);
        var updated = await ReadJsonAsync(await client.SendAsync(update, TestContext.Current.CancellationToken));

        Assert.Equal(clientId, Assert.Single(events.Of(EventIds.ClientUpdated)).Attributes["ClientId"]);

        using var removal = new HttpRequestMessage(HttpMethod.Delete, configuration);
        removal.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, updated[RegistrationResponse.RegistrationAccessToken]!.GetValue<string>());
        var removed = await client.SendAsync(removal, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);

        Assert.Equal(clientId, Assert.Single(events.Of(EventIds.ClientRemoved)).Attributes["ClientId"]);

        // Neither the secret nor a registration access token reaches a record
        AssertNoSecretReached(events, null, registered, updated);

        // Each endpoint's span names the client it served
        Assert.Equal(
            new[] { TelemetryEndpoints.RegisterClient, TelemetryEndpoints.RemoveClient, TelemetryEndpoints.UpdateClient },
            spans.Spans
                .Where(span => Equals(span.GetTagItem(TelemetryTags.ClientId), clientId))
                .Select(span => (string)span.GetTagItem(TelemetryTags.Endpoint)!)
                .Order());
    }

    private static HttpRequestMessage Authorized(HttpMethod method, Uri uri, JsonObject registered)
    {
        var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, registered[RegistrationResponse.RegistrationAccessToken]!.GetValue<string>());
        return request;
    }

    private static string Fingerprint(WebApplicationFactory<Program> host, string value)
        => host.Services.GetRequiredService<CredentialFingerprints>().Of(value).ToString();

    /// <summary>
    /// The members of a response that carry a token or a secret.
    /// </summary>
    private static readonly string[] SecretMembers =
    [
        TokenResponse.Parameters.AccessToken,
        TokenResponse.Parameters.RefreshToken,
        TokenResponse.Parameters.IdToken,
        RegistrationResponse.ClientSecret,
        RegistrationResponse.RegistrationAccessToken,
    ];

    /// <summary>
    /// No attribute of any record carries the raw subject or a token or a secret any of <paramref name="responses"/>
    /// handed out.
    /// </summary>
    private static void AssertNoSecretReached(OwnTraceEvents events, string? subject, params JsonObject[] responses)
    {
        var handedOut = responses
            .SelectMany(response => SecretMembers.Select(member => response[member]?.GetValue<string>()))
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(handedOut);

        foreach (var value in events.Events.SelectMany(record => record.Attributes.Values).OfType<string>())
        {
            Assert.DoesNotContain(value, handedOut);
            if (subject is not null)
                Assert.DoesNotContain(subject, value);
        }
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"{(int)response.StatusCode}: {body}");
        return JsonNode.Parse(body)!.AsObject();
    }
}
