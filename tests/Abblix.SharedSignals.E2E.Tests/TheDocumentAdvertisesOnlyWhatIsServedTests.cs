// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// What the configuration document claims about the Stream Management API, against what the deployment
/// actually answers.
/// </summary>
/// <remarks>
/// The document is the one artifact of a transmitter a stranger reads without being told anything (SSF 1.0
/// Section 7.1), and a receiver caches it. An address named there and not served is therefore a 404 the
/// receiver meets long after it read the document, with nothing on the transmitter's side to explain it -
/// the same failure the poll endpoint address avoids by being advertised only when there is one.
/// </remarks>
public sealed class TheDocumentAdvertisesOnlyWhatIsServedTests
{
    private const string Issuer = "https://transmitter.example";
    private const string DocumentRoute = "/.well-known/ssf-configuration";

    /// <summary>
    /// A transmitter that serves its streams from configuration needs no Stream Management API, and the
    /// documentation on the document mapper invites mapping the document alone. Such a deployment must not
    /// name five addresses nothing answers.
    /// </summary>
    [Fact]
    public async Task ADocumentMappedAlone_NamesNoManagementEndpoint()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(app => app.MapSharedSignalsConfigurationDocument());

        var document = await ReadDocumentAsync(host, cancellationToken);

        // Read as a group: the five members are one claim - "this transmitter has a management API" -
        // and a fix that suppressed some of them would leave the document claiming a half-API.
        Assert.Null(document.ConfigurationEndpoint);
        Assert.Null(document.StatusEndpoint);
        Assert.Null(document.AddSubjectEndpoint);
        Assert.Null(document.RemoveSubjectEndpoint);
        Assert.Null(document.VerificationEndpoint);
    }

    /// <summary>
    /// The deployment this option exists for, driven end to end: the document is mapped alone, the host
    /// names where the management API is served, and the document advertises exactly those addresses.
    /// </summary>
    /// <remarks>
    /// The two halves are covered apart - that the locator reads the host's source, and that a document
    /// with no source names nothing - and neither notices if the source stops reaching the document. This
    /// row is that seam. The addresses are asserted rather than their presence because the composed text
    /// is what a receiver caches, and a presence check passes over an address assembled wrongly.
    /// <para>
    /// Nothing is mapped here, so this row says nothing about which source wins. That is the row below.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ADocumentMappedAlone_NamesWhatTheHostSaidIsServed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            app => app.MapSharedSignalsConfigurationDocument(),
            ManagementEndpointLocator.Under(new Uri("https://gateway.example/ssf")));

        var document = await ReadDocumentAsync(host, cancellationToken);

        Assert.Equal("https://gateway.example/ssf/stream", document.ConfigurationEndpoint!.AbsoluteUri);
        Assert.Equal("https://gateway.example/ssf/status", document.StatusEndpoint!.AbsoluteUri);
        Assert.Equal(
            "https://gateway.example/ssf/subjects:add", document.AddSubjectEndpoint!.AbsoluteUri);
        Assert.Equal(
            "https://gateway.example/ssf/subjects:remove", document.RemoveSubjectEndpoint!.AbsoluteUri);
        Assert.Equal("https://gateway.example/ssf/verify", document.VerificationEndpoint!.AbsoluteUri);
    }

    /// <summary>
    /// A transmitter reached through a gateway: it maps the management routes itself AND the host names
    /// where the outside world reaches them. The document names the gateway.
    /// </summary>
    /// <remarks>
    /// This is the deployment the option exists for, and the only place the precedence between the two
    /// sources is visible in what a receiver actually reads. Reversing it - the mapping winning over the
    /// host - publishes the internal addresses to the outside world, which no row above would notice:
    /// the one that maps nothing has no mapped address to lose to, and the one that names no source has
    /// no host address to be overridden.
    /// </remarks>
    [Fact]
    public async Task AMappedTransmitterWhoseHostNamesAGateway_AdvertisesTheGateway()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(
            app => app.MapSharedSignalsTransmitterEndpoints(),
            ManagementEndpointLocator.Under(new Uri("https://gateway.example/ssf")));

        var document = await ReadDocumentAsync(host, cancellationToken);

        Assert.Equal("https://gateway.example/ssf/stream", document.ConfigurationEndpoint!.AbsoluteUri);
        Assert.Equal("https://gateway.example/ssf/verify", document.VerificationEndpoint!.AbsoluteUri);
    }

    /// <summary>
    /// The control, and the half this change must not break: a transmitter that does map the management
    /// API still advertises it.
    /// </summary>
    /// <remarks>
    /// Without this row, suppressing the members unconditionally would pass the row above, and the
    /// document of an ordinary deployment would stop naming addresses that work.
    /// </remarks>
    [Fact]
    public async Task ADocumentOfAMappedTransmitter_NamesTheManagementEndpoints()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(app => app.MapSharedSignalsTransmitterEndpoints());

        var document = await ReadDocumentAsync(host, cancellationToken);

        Assert.NotNull(document.ConfigurationEndpoint);
        Assert.NotNull(document.StatusEndpoint);
        Assert.NotNull(document.AddSubjectEndpoint);
        Assert.NotNull(document.RemoveSubjectEndpoint);
        Assert.NotNull(document.VerificationEndpoint);
    }

    /// <summary>
    /// The addresses a mapped transmitter advertises are addresses it answers. Asserted by USING one,
    /// because a row reading the document alone passes over a URL pointing anywhere at all.
    /// </summary>
    [Fact]
    public async Task AnAdvertisedManagementAddress_IsAnsweredRatherThanA404()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(app => app.MapSharedSignalsTransmitterEndpoints());

        var document = await ReadDocumentAsync(host, cancellationToken);
        using var answered = await host.GetTestClient().GetAsync(
            document.ConfigurationEndpoint!.PathAndQuery, cancellationToken);

        // Unauthorized rather than OK: the route requires a caller, and this test names none. What
        // matters is that something is mapped there - a 404 would mean the document named nothing.
        Assert.Equal(HttpStatusCode.Unauthorized, answered.StatusCode);
    }

    private static Task<TransmitterConfiguration> ReadDocumentAsync(
        WebApplication host,
        CancellationToken cancellationToken)
        => host.GetTestClient().GetFromJsonAsync<TransmitterConfiguration>(DocumentRoute, cancellationToken)!;

    private static async Task<WebApplication> StartAsync(
        Action<WebApplication> map,
        Func<string, Uri>? managementEndpointFactory = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        builder.Services.AddSecurityEvents(o =>
            o.SigningKeySource = _ => Task.FromResult<JsonWebKey>(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Issuer,
            ManagementEndpointFactory = managementEndpointFactory,
        });
        builder.Services.AddSingleton(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = _ => null,
        });

        var app = builder.Build();
        map(app);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }
}
