// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// A client resolved from its metadata document is recorded by the lookup that first holds it for the tenant, never by
/// a lookup reading the client held, and a document the tenant refuses records no resolution. The record of a client
/// the tenant admits, which takes every registration check this fixture does not wire, is read through a running host
/// (ClientIdMetadataDocumentTests in the E2E suite).
/// </summary>
public sealed class ClientResolvedLogTests : IDisposable
{
    private const string ClientId = "https://client.example.com/metadata.json";

    private const string Document = """{"client_id":"https://client.example.com/metadata.json"}""";

    private static readonly TenantDefinition Tenant = new() { Id = "tenant", Issuer = new Uri("https://issuer.example.com") };

    private readonly MetadataDocumentServices _services = new();
    private readonly RecordingLoggerFactory _logs = new();

    public void Dispose() => _services.Dispose();

    private ClientIdMetadataDocumentClients CreateClients()
    {
        var store = new Mock<IClientInfoProvider>();
        store
            .Setup(s => s.FindClientAsync(It.IsAny<TenantDefinition>(), It.IsAny<string>()))
            .ReturnsAsync(ClientAbsence.Unknown);
        return new ClientIdMetadataDocumentClients(
            store.Object,
            new Logger<ClientIdMetadataDocumentClients>(_logs),
            _services.Get<HeldMetadataDocuments>(),
            _services.Get<IServiceScopeFactory>(),
            _services.Get<IOptionsMonitor<OidcOptions>>(),
            new ProductionEnvironment(_services.Provider));
    }

    private LogRecord[] Resolved => _logs.Entries
        .Where(entry => entry.EventId.Id == LogEvents.ClientInformation.ClientIdMetadataDocuments.ClientResolved)
        .ToArray();

    [Fact]
    public async Task ADocumentTheTenantRefuses_RecordsNoResolution()
    {
        _services.Origin.Serve(
            ClientId, """{"client_id":"https://client.example.com/metadata.json","redirect_uris":["javascript:x"]}""");

        Assert.False((await CreateClients().FindClientAsync(Tenant, ClientId)).TryGetSuccess(out _));

        Assert.Empty(Resolved);
    }

    /// <summary>
    /// Two lookups of one document that both judged its client before either held it: the first to hold its client
    /// records the resolution, the one that lost the race is handed the client held and records nothing.
    /// </summary>
    [Fact]
    public void OfTwoLookupsHoldingAClientForOneDocument_OnlyTheFirstRecordsIt()
    {
        var document = new HeldMetadataDocument(Document, DateTimeOffset.UnixEpoch);
        var clients = CreateClients();
        var first = new ClientInfo(ClientId);

        Assert.Same(first, clients.Keep(Tenant, document, first));
        Assert.Same(first, clients.Keep(Tenant, document, new ClientInfo(ClientId)));

        var record = Assert.Single(Resolved);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(Tenant.Id, record.Value("TenantId"));
        Assert.Equal(ClientId, record.Value("ClientId")?.ToString());
        Assert.Equal(
            first.EffectiveGrantTypes,
            Assert.IsType<Sanitized[]>(record.Value("GrantTypes")).Select(value => value.ToString()));
    }

    /// <summary>
    /// Two lookups racing to hold a client for one tenant: the one holding it first is told so, the other is handed
    /// the client held and told it is not its own, so only the first records it.
    /// </summary>
    [Fact]
    public void OfTwoClientsHeldForOneTenant_OnlyTheFirstIsHeld()
    {
        var document = new HeldMetadataDocument(Document, DateTimeOffset.UnixEpoch);
        var first = new ClientInfo(ClientId);
        var second = new ClientInfo(ClientId);

        Assert.True(document.TryHold(Tenant, first, out var heldFirst));
        Assert.Same(first, heldFirst);
        Assert.False(document.TryHold(Tenant, second, out var heldSecond));
        Assert.Same(first, heldSecond);
        Assert.Same(first, document.ClientAt(Tenant));
    }
}
