// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Reflection;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using RegistrationRequest = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A running server records each request, each token it hands out, each signing, each registration and each
/// refusal for a spent budget into its meter, with only the attributes and values the server's table admits.
/// </summary>
public sealed class EndpointMetricsTests(TestFactory factory) : TestBase(factory)
{
    private const string UnknownGrantType = "urn:example:grant-of-the-client";

    [Fact]
    public async Task A_running_server_records_each_instrument_with_admitted_attributes()
    {
        // A host of its own, so the meter it measures into is not shared with tests running alongside, and a
        // budget of one introspection, so the second one is refused
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(
            services => services.PostConfigure<OidcOptions>(options => options.CallerRateLimit = new CallerRateLimitOptions
            {
                PermitLimit = 1,
                Window = TimeSpan.FromHours(1),
            })));
        var measured = new ConcurrentQueue<(string Instrument, Dictionary<string, object?> Tags)>();
        using var listener = Listen(host.Services.GetRequiredService<IMeterFactory>(), measured);
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        await DriveAsync(client);

        Dictionary<string, object?>[] Of(string instrument)
            => measured.Where(m => m.Instrument == instrument).Select(m => m.Tags).ToArray();

        var tokenRequests = Of(OidcMetrics.RequestDuration)
            .Where(tags => Equals(tags[TelemetryTags.Endpoint], TelemetryEndpoints.Token))
            .ToArray();
        Assert.Contains(tokenRequests, tags => Equals(tags[TelemetryTags.Outcome], TelemetryOutcomes.Success));
        Assert.Contains(tokenRequests, tags => Equals(tags[TelemetryTags.Outcome], TelemetryOutcomes.Refused) &&
                                               Equals(tags[TelemetryTags.Error], ErrorCodes.UnauthorizedClient));

        Assert.Equal(
            new[] { TelemetryTokenTypes.AccessToken, TelemetryTokenTypes.IdToken, TelemetryTokenTypes.RefreshToken },
            Of(OidcMetrics.TokensIssued).Select(tags => tags[TelemetryTags.TokenType]).Order());
        Assert.All(
            Of(OidcMetrics.TokensIssued),
            tags => Assert.Equal(GrantTypes.AuthorizationCode, tags[TelemetryTags.GrantType]));

        Assert.NotEmpty(Of(OidcMetrics.TokenSigningDuration));
        Assert.NotEmpty(Of(OidcMetrics.StorageOperationDuration));
        Assert.Equal(TelemetryOutcomes.Success, Assert.Single(Of(OidcMetrics.ClientsRegistered))[TelemetryTags.Outcome]);

        var spent = Assert.Single(Of(OidcMetrics.RateLimitRefusals));
        Assert.Equal(TelemetryEndpoints.Introspection, spent[TelemetryTags.Endpoint]);
        Assert.Equal(CallerRateLimiters.Introspection, spent[TelemetryTags.RateLimitBudget]);

        AssertOnlyAdmittedAttributes(host.Services, measured.SelectMany(m => m.Tags));
    }

    /// <summary>
    /// Every attribute is one of the server's, and every value one of its key's set. No measurement of a server
    /// without tenants names one.
    /// </summary>
    private static void AssertOnlyAdmittedAttributes(
        IServiceProvider services,
        IEnumerable<KeyValuePair<string, object?>> tags)
    {
        var endpoints = ConstantsOf(typeof(TelemetryEndpoints));
        var outcomes = ConstantsOf(typeof(TelemetryOutcomes));
        var errors = ConstantsOf(typeof(ErrorCodes));
        var tokenTypes = ConstantsOf(typeof(TelemetryTokenTypes));
        var algorithms = ConstantsOf(typeof(SigningAlgorithms));
        var budgets = ConstantsOf(typeof(CallerRateLimiters));
        var reasons = ConstantsOf(typeof(LicenseRefusalReasons));
        var storageOperations = ConstantsOf(typeof(TelemetryStorageOperations));
        using var scope = services.CreateScope();
        var grantTypes = scope.ServiceProvider.GetRequiredService<IAuthorizationGrantHandler>().GrantTypesSupported
            .Append(GrantTypes.Implicit)
            .ToHashSet();

        foreach (var (key, value) in tags)
        {
            var text = Assert.IsType<string>(value);
            var admitted = key switch
            {
                TelemetryTags.Endpoint => endpoints.Contains(text),
                TelemetryTags.Outcome => outcomes.Contains(text),
                TelemetryTags.Error => errors.Contains(text),
                TelemetryTags.TokenType => tokenTypes.Contains(text),
                TelemetryTags.GrantType => grantTypes.Contains(text),
                TelemetryTags.SigningAlgorithm => algorithms.Contains(text),
                TelemetryTags.RateLimitBudget => budgets.Contains(text),
                TelemetryTags.LicenseRefusalReason => reasons.Contains(text),
                TelemetryTags.StorageOperation => storageOperations.Contains(text),
                _ => false,
            };
            Assert.True(admitted, $"{key} = {text} is not admitted");
        }
    }

    private static HashSet<string> ConstantsOf(Type type) => type
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field is { IsLiteral: true } && field.FieldType == typeof(string))
        .Select(field => (string)field.GetRawConstantValue()!)
        .ToHashSet(StringComparer.Ordinal);

    private static MeterListener Listen(
        IMeterFactory factory,
        ConcurrentQueue<(string Instrument, Dictionary<string, object?> Tags)> measured)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == OidcTelemetry.SourceName && ReferenceEquals(instrument.Meter.Scope, factory))
                    listener.EnableMeasurementEvents(instrument);
            },
        };
        listener.SetMeasurementEventCallback<double>(
            (instrument, _, tags, _) => measured.Enqueue((instrument.Name, new Dictionary<string, object?>(tags.ToArray()))));
        listener.SetMeasurementEventCallback<long>(
            (instrument, _, tags, _) => measured.Enqueue((instrument.Name, new Dictionary<string, object?>(tags.ToArray()))));
        listener.Start();
        return listener;
    }

    private static async Task DriveAsync(HttpClient client)
    {
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        var refusal = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.GrantType] = UnknownGrantType,
        });
        Assert.False(refusal.IsSuccessStatusCode);

        await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationRequest.ClientName] = "measured-client",
            [RegistrationRequest.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials),
            [RegistrationRequest.ResponseTypes] = new JsonArray(),
            [RegistrationRequest.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
        });

        await IntrospectAsync(client, discovery, accessToken, TestConstants.ConfidentialClientId);
        var spent = await FormPostHelpers.PostFormAsync(client, discovery.IntrospectionEndpoint!, new Dictionary<string, string>
        {
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [IntrospectionRequest.Parameters.Token] = accessToken,
        });
        Assert.Equal(HttpStatusCode.TooManyRequests, spent.StatusCode);
    }
}
