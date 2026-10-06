// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using RegistrationRequest = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using RegistrationResponse = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Each endpoint request runs in a span of the server's source, a child of the host's HTTP server span, carrying only
/// the attributes and values the server's table admits.
/// </summary>
public sealed class EndpointSpanTests(TestFactory factory) : TestBase(factory), IDisposable
{
    private const string HostingSource = "Microsoft.AspNetCore";
    private const string UnknownGrantType = "urn:example:grant-of-the-client";

    private readonly ConcurrentBag<Activity> _stopped = [];
    private ActivityListener? _listener;

    public void Dispose() => _listener?.Dispose();

    [Fact]
    public async Task A_full_flow_runs_in_endpoint_spans_carrying_only_admitted_attributes()
    {
        _listener = new ActivityListener
        {
            // Both sources: without a listener on hosting, no HTTP server span exists to parent the endpoint spans
            ShouldListenTo = source => source.Name is OidcTelemetry.SourceName or HostingSource,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => _stopped.Add(activity),
        };
        ActivitySource.AddActivityListener(_listener);

        // Every request of this test carries one trace, so the spans of tests running alongside are told apart
        var trace = ActivityTraceId.CreateRandom();
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("traceparent", $"00-{trace}-{ActivitySpanId.CreateRandom()}-01");

        await DriveFlowAsync(client);

        var spans = _stopped.Where(span => span.Source.Name == OidcTelemetry.SourceName && span.TraceId == trace).ToArray();
        var endpointSpans = spans.Where(span => span.GetTagItem(TelemetryTags.Endpoint) is not null).ToArray();
        var stageSpans = spans.Except(endpointSpans).ToArray();

        Assert.Equal(
            new[]
            {
                TelemetryEndpoints.Configuration, TelemetryEndpoints.Authorize, TelemetryEndpoints.Token,
                TelemetryEndpoints.UserInfo, TelemetryEndpoints.Introspection, TelemetryEndpoints.Revocation,
                TelemetryEndpoints.RegisterClient, TelemetryEndpoints.DeviceAuthorization,
                TelemetryEndpoints.PushedAuthorization, TelemetryEndpoints.ReadClient, TelemetryEndpoints.EndSession,
                TelemetryEndpoints.CheckSession,
            }.Order(),
            endpointSpans.Select(span => (string)span.GetTagItem(TelemetryTags.Endpoint)!).Distinct().Order());

        // An endpoint's span sits under the host's request, and each stage's under the endpoint's span or another stage
        Assert.All(endpointSpans, span => Assert.Equal(HostingSource, span.Parent?.Source.Name));
        Assert.NotEmpty(stageSpans);
        Assert.All(stageSpans, span => Assert.Equal(OidcTelemetry.SourceName, span.Parent?.Source.Name));
        AssertOnlyAdmittedAttributes(spans);

        var refused = Assert.Single(spans, span => Equals(span.GetTagItem(TelemetryTags.Error), ErrorCodes.UnauthorizedClient));
        Assert.Equal(ActivityStatusCode.Error, refused.Status);
        Assert.Null(refused.GetTagItem(TelemetryTags.GrantType));
        Assert.Contains(spans, span => span.Status == ActivityStatusCode.Ok &&
                                       Equals(span.GetTagItem(TelemetryTags.GrantType), GrantTypes.AuthorizationCode));
    }

    /// <summary>
    /// Every attribute is one of the server's, and every value one of its key's set: the endpoints, the stages, the grant types
    /// the host serves, the response types and the library's error codes, so no span of this flow, which runs no handler
    /// of the host's, names an error code as unknown. No span of a server without tenants
    /// names one, and none of this flow fails with an exception.
    /// </summary>
    private void AssertOnlyAdmittedAttributes(Activity[] spans)
    {
        var endpoints = ConstantsOf(typeof(TelemetryEndpoints));
        var stages = ConstantsOf(typeof(TelemetryStages));
        var errors = ConstantsOf(typeof(ErrorCodes));
        var responseTypes = ConstantsOf(typeof(ResponseTypes));
        using var scope = Factory.Services.CreateScope();
        var grantTypes = scope.ServiceProvider.GetRequiredService<IAuthorizationGrantHandler>().GrantTypesSupported.ToHashSet();

        foreach (var (key, value) in spans.SelectMany(span => span.Tags))
        {
            Assert.True(value is not null, $"{key} has no value");
            var admitted = key switch
            {
                TelemetryTags.Endpoint => endpoints.Contains(value),
                TelemetryTags.Stage => stages.Contains(value),
                TelemetryTags.GrantType => grantTypes.Contains(value),
                TelemetryTags.ResponseType => value.Split(' ') is var parts &&
                                              parts.All(responseTypes.Contains) &&
                                              value == string.Join(' ', parts.Distinct().Order(StringComparer.Ordinal)),
                TelemetryTags.Error => errors.Contains(value),
                _ => false,
            };
            Assert.True(admitted, $"{key} = {value} is not admitted");
        }
    }

    private static HashSet<string> ConstantsOf(Type type) => type
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field is { IsLiteral: true } && field.FieldType == typeof(string))
        .Select(field => (string)field.GetRawConstantValue()!)
        .ToHashSet(StringComparer.Ordinal);

    private static async Task DriveFlowAsync(HttpClient client)
    {
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        using (var userInfo = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint))
        {
            userInfo.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
            (await client.SendAsync(userInfo, TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();
        }

        await IntrospectAsync(client, discovery, accessToken, TestConstants.ConfidentialClientId);

        var refreshed = await ExchangeCodeForTokensAsync(client, discovery, Confidential(
            (TokenRequest.Parameters.GrantType, GrantTypes.RefreshToken),
            (TokenRequest.Parameters.RefreshToken, refreshToken)));

        (await FormPostHelpers.PostFormAsync(client, discovery.RevocationEndpoint!, Confidential(
            (RevocationRequest.Parameters.Token, refreshed[TokenRequest.Parameters.RefreshToken]!.GetValue<string>()))))
            .EnsureSuccessStatusCode();

        var refusal = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, Confidential(
            (TokenRequest.Parameters.GrantType, UnknownGrantType)));
        Assert.False(refusal.IsSuccessStatusCode);

        var device = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationRequest.ClientName] = "traced-device",
            [RegistrationRequest.GrantTypes] = new JsonArray(GrantTypes.DeviceAuthorization),
            [RegistrationRequest.ResponseTypes] = new JsonArray(),
            [RegistrationRequest.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
        });
        (await FormPostHelpers.PostFormAsync(client, discovery.DeviceAuthorizationEndpoint!, new Dictionary<string, string>
        {
            [DeviceAuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [ClientRequest.Parameters.ClientId] = device[RegistrationResponse.ClientId]!.GetValue<string>(),
            [ClientRequest.Parameters.ClientSecret] = device[RegistrationResponse.ClientSecret]!.GetValue<string>(),
        })).EnsureSuccessStatusCode();

        using (var readClient = new HttpRequestMessage(
                   HttpMethod.Get, device[RegistrationResponse.RegistrationClientUri]!.GetValue<string>()))
        {
            readClient.Headers.Authorization = new AuthenticationHeaderValue(
                TokenTypes.Bearer, device[RegistrationResponse.RegistrationAccessToken]!.GetValue<string>());
            (await client.SendAsync(readClient, TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();
        }

        await PushAuthorizationRequestAsync(client, discovery, Confidential(
            (AuthorizationRequest.Parameters.ResponseType, ResponseTypes.Code),
            (AuthorizationRequest.Parameters.RedirectUri, TestConstants.RedirectUri),
            (AuthorizationRequest.Parameters.Scope, Scopes.OpenId),
            (AuthorizationRequest.Parameters.CodeChallenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            (AuthorizationRequest.Parameters.CodeChallengeMethod, CodeChallengeMethods.S256)));

        // Answered whatever they say: the span is what this test is after
        await client.GetAsync(discovery.EndSessionEndpoint, TestContext.Current.CancellationToken);
        await client.GetAsync(discovery.CheckSessionIframe, TestContext.Current.CancellationToken);
    }

    private static Dictionary<string, string> Confidential(params (string Key, string Value)[] parameters)
    {
        var form = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
        foreach (var (key, value) in parameters)
            form[key] = value;
        return form;
    }
}
