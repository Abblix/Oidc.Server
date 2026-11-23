// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Tests.Shared;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// Draft-ietf-oauth-client-id-metadata-document section 10.7's exception: a server "MAY relax this restriction to allow
/// fetching from loopback addresses when the authorization server itself is also running on a loopback address".
/// Driven from the client lookup through the registration a host makes, with the SSRF validation as the transport's
/// primary handler and only its resolution and its origin replaced, so every check that refuses loopback - the
/// identifier's literal, the fetch's own check of the name, the handler's check of it and the address the connection is
/// made to - answers the one decision.
/// </summary>
public sealed class LoopbackDocumentsTests
{
    private const string PublicIssuer = "https://issuer.example.com/";

    private const ClientIdMetadataDocumentAddresses Loopback = ClientIdMetadataDocumentAddresses.AllowLoopback;

    /// <summary>
    /// What each name a row asks for resolves to; a name missing here is a question the row did not mean to ask.
    /// </summary>
    private static readonly Dictionary<string, IPAddress[]> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        ["localhost"] = [IPAddress.Loopback, IPAddress.IPv6Loopback],
        ["dev.example.com"] = [IPAddress.Loopback],
        ["intranet.example.com"] = [IPAddress.Parse("10.0.0.5")],
        ["mixed.example.com"] = [IPAddress.Loopback, IPAddress.Parse("192.168.1.5")],
        ["keys.example.com"] = [IPAddress.Parse("93.184.216.34")],
    };

    private readonly MetadataDocumentOrigin _origin = new();
    private readonly EventCapture _events = new();

    public static TheoryData<string, string> LoopbackDocuments() => new()
    {
        { "https://localhost:5001/", "https://localhost:5002/client.json" },
        { "https://localhost:5001/", "https://dev.example.com/client.json" },
        { "https://127.0.0.1:5001/", "https://127.0.0.1:5002/client.json" },
        { "https://127.0.0.1:5001/", "https://[::1]:5002/client.json" },
        { "https://[::1]:5001/", "https://localhost:5002/client.json" },
        { "http://localhost:5000/", "https://127.0.0.2/client.json" },
    };

    [Theory]
    [MemberData(nameof(LoopbackDocuments))]
    public async Task ALoopbackDocument_IsFetched_WhenAllowedAndTheIssuerIsOnLoopback(string issuer, string clientId)
    {
        Assert.Equal(1, await RequestsOfALookUpAsync(Loopback, issuer, clientId));
    }

    [Theory]
    [MemberData(nameof(LoopbackDocuments))]
    public async Task ALoopbackDocument_IsRefused_WhenNotAllowed(string issuer, string clientId)
    {
        Assert.Equal(0, await RequestsOfALookUpAsync(ClientIdMetadataDocumentAddresses.PublicOnly, issuer, clientId));
    }

    /// <summary>
    /// The same section: authorization servers "MUST NOT apply this exception in production deployments", so a tenant
    /// whose issuer is not on loopback gets nothing from the setting.
    /// </summary>
    [Theory]
    [MemberData(nameof(LoopbackDocuments))]
    public async Task ALoopbackDocument_IsRefused_WhenTheIssuerIsNotOnLoopback(string _, string clientId)
    {
        Assert.Equal(0, await RequestsOfALookUpAsync(Loopback, PublicIssuer, clientId));
    }

    /// <summary>
    /// A host that set the exception and runs a tenant on a public issuer is told why a loopback client is refused
    /// there, apart from every other refusal; a tenant on loopback is told nothing, and neither is a host that did not
    /// set it.
    /// </summary>
    [Theory]
    [InlineData(Loopback, PublicIssuer, "https://localhost:5002/client.json", true)]
    [InlineData(Loopback, PublicIssuer, "https://[::1]:5002/client.json", true)]
    [InlineData(Loopback, "https://localhost:5001/", "https://localhost:5002/client.json", false)]
    [InlineData(ClientIdMetadataDocumentAddresses.PublicOnly, PublicIssuer, "https://localhost:5002/client.json", false)]
    [InlineData(Loopback, PublicIssuer, "https://client.example.com/client.json", false)]
    public async Task ALoopbackClientAtAPublicIssuer_IsRefusedWithTheReason(
        ClientIdMetadataDocumentAddresses addresses,
        string issuer,
        string clientId,
        bool told)
    {
        await RequestsOfALookUpAsync(addresses, issuer, clientId);

        Assert.Equal(
            told,
            _events.Ids.Contains(LogEvents.ClientInformation.ClientIdMetadataDocuments.LoopbackWithheld));
    }

    /// <summary>
    /// Section 10.7: servers "MUST NOT apply this exception in production deployments". A Production host that started
    /// with the exception off and had it turned on by a configuration reload still fetches nothing from loopback, at a
    /// tenant whose issuer is on loopback.
    /// </summary>
    [Fact]
    public async Task AProductionHost_FetchesNoLoopbackDocument_WhenTheSettingChangesAfterStart()
    {
        const string clientId = "https://localhost:5002/client.json";
        var services = Services(ClientIdMetadataDocumentAddresses.PublicOnly);
        services.AddSingleton(Mock.Of<IHostEnvironment>(host => host.EnvironmentName == Environments.Production));
        var reloaded = new OidcOptions
        {
            ClientIdMetadataDocuments = { Enabled = true, DocumentAddresses = Loopback },
        };
        services.AddSingleton(Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == reloaded));
        _origin.Serve(clientId, """{"client_id":"https://another.example.com/client.json"}""");

        await using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(TestContext.Current.CancellationToken);

        Assert.Null(await provider.GetRequiredService<IClientInfoProvider>()
            .TryFindClientAsync(Tenant("https://localhost:5001/"), clientId));
        Assert.Equal(0, _origin.RequestsTo(clientId));
    }

    /// <summary>
    /// The exception covers the document's own URL alone: a key set the document names on loopback is fetched by the
    /// strict rule, even from inside a scope that reaches loopback, while one on a public name is fetched.
    /// </summary>
    [Theory]
    [InlineData("https://localhost:5003/jwks", 0)]
    [InlineData("https://127.0.0.1:5003/jwks", 0)]
    [InlineData("https://keys.example.com/jwks", 1)]
    public async Task AKeySetADocumentNames_IsHeldToTheStrictRule(string jwksUri, int requests)
    {
        _origin.Serve(jwksUri, KeySet);
        await using var provider = Services(Loopback).BuildServiceProvider();
        var keys = new ClientKeysProvider(NullLogger<ClientKeysProvider>.Instance, provider);
        var client = new ClientInfo("https://localhost:5002/client.json")
        {
            JwksUri = new Uri(jwksUri),
            ResolvedFromMetadataDocument = true,
        };

        using (SpecialPurposeFetches.Enter(OutboundAddressRule.NoSpecialPurposeButLoopback))
            await keys.GetSigningKeys(client).ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.Equal(requests, _origin.RequestsTo(jwksUri));
    }

    private static readonly string KeySet = JsonSerializer.Serialize(new JsonWebKeySet(
    [
        JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256).Sanitize(includePrivateKeys: false),
    ]));

    /// <summary>
    /// The exception reaches loopback alone: a private network, written as a literal or reached through a name, and a
    /// name answering with loopback and a private address together, are refused as before.
    /// </summary>
    [Theory]
    [InlineData("https://10.0.0.5/client.json")]
    [InlineData("https://192.168.1.5/client.json")]
    [InlineData("https://intranet.example.com/client.json")]
    [InlineData("https://mixed.example.com/client.json")]
    public async Task APrivateDocument_IsRefused_WhenLoopbackIsAllowed(string clientId)
    {
        Assert.Equal(0, await RequestsOfALookUpAsync(Loopback, "https://localhost:5001/", clientId));
    }

    /// <summary>
    /// A document is held once for every tenant, so one a fetch reached loopback for is held apart from one fetched by
    /// the strict rule and never answers a lookup made by it, in either order.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ADocumentHeldByTheLoopbackRule_DoesNotAnswerTheStrictOne(bool loopbackFirst)
    {
        const string clientId = "https://dev.example.com/client.json";
        _origin.Serve(clientId, $$"""{"client_id":"{{clientId}}"}""", "max-age=60");
        await using var provider = Services(Loopback).BuildServiceProvider();
        var documents = provider.GetRequiredService<HeldMetadataDocuments>();

        foreach (var rule in loopbackFirst
                     ? new[] { OutboundAddressRule.NoSpecialPurposeButLoopback, OutboundAddressRule.NoSpecialPurpose }
                     : [OutboundAddressRule.NoSpecialPurpose, OutboundAddressRule.NoSpecialPurposeButLoopback])
        {
            var held = await documents.GetAsync(clientId, new Uri(clientId), rule);
            Assert.Equal(rule == OutboundAddressRule.NoSpecialPurposeButLoopback, held is not null);
        }

        Assert.Equal(1, _origin.RequestsTo(clientId));
    }

    /// <summary>
    /// A lookup by the strict rule made while a fetch by the loopback rule is in flight does not join it: it makes a
    /// fetch of its own, which is refused.
    /// </summary>
    [Fact]
    public async Task ALookupByTheStrictRule_DoesNotJoinAFetchByTheLoopbackRule()
    {
        const string clientId = "https://dev.example.com/client.json";
        var release = new TaskCompletionSource();
        _origin.AnswerAsync(clientId, async () =>
        {
            await release.Task;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""{"client_id":"{{clientId}}"}""", Encoding.UTF8, "application/json"),
            };
        });
        await using var provider = Services(Loopback).BuildServiceProvider();
        var documents = provider.GetRequiredService<HeldMetadataDocuments>();

        var loopback = documents.GetAsync(clientId, new Uri(clientId), OutboundAddressRule.NoSpecialPurposeButLoopback);
        while (_origin.RequestsTo(clientId) == 0)
            await Task.Delay(TimeSpan.FromMilliseconds(5), TestContext.Current.CancellationToken);
        var strict = documents.GetAsync(clientId, new Uri(clientId), OutboundAddressRule.NoSpecialPurpose);
        release.SetResult();

        Assert.NotNull(await loopback);
        Assert.Null(await strict);
        Assert.Equal(1, _origin.RequestsTo(clientId));
    }

    /// <summary>
    /// How many requests a lookup of <paramref name="clientId"/> at a tenant issuing as <paramref name="issuer"/> sent
    /// to the origin: whether the document is fetched is the subject, so it names another client and is refused once
    /// read, before the tenant judges what it describes.
    /// </summary>
    private async Task<int> RequestsOfALookUpAsync(ClientIdMetadataDocumentAddresses addresses, string issuer, string clientId)
    {
        _origin.Serve(clientId, """{"client_id":"https://another.example.com/client.json"}""");
        await using var provider = Services(addresses).BuildServiceProvider();
        Assert.Null(await provider.GetRequiredService<IClientInfoProvider>().TryFindClientAsync(Tenant(issuer), clientId));
        return _origin.RequestsTo(clientId);
    }

    private static TenantDefinition Tenant(string issuer) => new() { Id = "tenant", Issuer = new Uri(issuer) };

    private ServiceCollection Services(ClientIdMetadataDocumentAddresses addresses)
    {
        var services = Unguarded(addresses);
        Guard(services, ClientIdMetadataDocumentTransport.HttpClientName);
        Guard(services, SecureFetchTransport.HttpClientName);
        return services;
    }

    /// <summary>
    /// Makes the client registered as <paramref name="name"/> send through the SSRF validation over the names this
    /// class resolves, to the origin.
    /// </summary>
    private void Guard(IServiceCollection services, string name)
        => services.AddHttpClient(name)
            .ConfigurePrimaryHttpMessageHandler(provider =>
            {
                var guard = new SsrfValidatingHttpMessageHandler(
                    provider.GetRequiredService<IOptions<SecureHttpFetchOptions>>(),
                    provider.GetRequiredService<ISecureUriValidator>(),
                    (host, _) => Task.FromResult(Names[host]));

                // The judgement is made in the guard's send, before its inner handler; only the dial is replaced
                guard.InnerHandler!.Dispose();
                guard.InnerHandler = _origin;
                return guard;
            });

    private ServiceCollection Unguarded(ClientIdMetadataDocumentAddresses addresses)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(_events));
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddSingleton(Mock.Of<IClientInfoProvider>());
        new Registered(services).AddClientIdMetadataDocuments();
        services.Configure<OidcOptions>(options => options.ClientIdMetadataDocuments.DocumentAddresses = addresses);

        services.AddSingleton(Mock.Of<IClientAuthenticator>(authenticator =>
            authenticator.ClientAuthenticationMethodsSupported == new[] { ClientAuthenticationMethods.None }));
        services.AddSingleton(Mock.Of<IGrantTypeInformer>(informer =>
            informer.GrantTypesSupported == new[] { GrantTypes.AuthorizationCode }));
        services.AddSingleton(Mock.Of<IAuthorizationResponseBuilder>(builder => builder.ResponseType == ResponseTypes.Code));
        return services;
    }

    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }

    /// <summary>
    /// The event ids the lookup logged.
    /// </summary>
    private sealed class EventCapture : ILoggerProvider
    {
        private readonly ConcurrentQueue<int> _ids = new();

        public IReadOnlyCollection<int> Ids => _ids;

        public ILogger CreateLogger(string categoryName) => new Capturing(_ids);

        public void Dispose()
        {
        }

        private sealed class Capturing(ConcurrentQueue<int> ids) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => ids.Enqueue(eventId.Id);
        }
    }
}
