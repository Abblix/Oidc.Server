// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// Which client identifiers the store's decorator resolves from a document, and which it leaves to the store or
/// refuses before any fetch.
/// </summary>
public sealed class ClientIdMetadataDocumentClientsTests : IDisposable
{
    private const string ClientId = "https://client.example.com/metadata.json";
    private const string Document = """{"client_id":"https://client.example.com/metadata.json"}""";

    private readonly MetadataDocumentServices _services = new();
    private readonly Mock<IClientInfoProvider> _store = new();

    private static readonly TenantDefinition Tenant = new()
    {
        Id = "tenant",
        Issuer = new Uri("https://issuer.example.com/"),
        Resources = [new ResourceDefinition(new Uri("https://api.example.com/orders"))],
    };

    public void Dispose() => _services.Dispose();

    private ClientIdMetadataDocumentClients CreateClients() => new(
        _store.Object,
        NullLogger<ClientIdMetadataDocumentClients>.Instance,
        _services.Get<HeldMetadataDocuments>(),
        _services.Get<IServiceScopeFactory>(),
        _services.Get<IOptionsMonitor<OidcOptions>>());

    /// <summary>
    /// Section 9.2: a server "MAY pre-register Client Identifier URLs", and a client so configured is served as
    /// configured, without a fetch.
    /// </summary>
    [Fact]
    public async Task AClientTheStoreKnows_IsServedFromTheStore_WithoutAFetch()
    {
        var stored = new ClientInfo(ClientId);
        _store.Setup(store => store.TryFindClientAsync(Tenant, ClientId)).ReturnsAsync(stored);
        _services.Origin.Serve(ClientId, Document);

        Assert.Same(stored, await CreateClients().TryFindClientAsync(Tenant, ClientId));
        Assert.Empty(_services.Origin.Requests);
    }

    [Theory]
    [InlineData("client-1")]
    [InlineData("http://client.example.com/metadata.json")]
    [InlineData("https://client.example.com/metadata.json?x=1")]
    public async Task AnIdentifierThatIsNoClientIdentifierUrl_IsUnknown_WithoutAFetch(string clientId)
    {
        _services.Origin.Serve(clientId, Document);

        Assert.Null(await CreateClients().TryFindClientAsync(Tenant, clientId));
        Assert.Empty(_services.Origin.Requests);
    }

    [Fact]
    public async Task AUrlOutsideTheAllowList_IsUnknown_WithoutAFetch()
    {
        _services.Options.ClientIdMetadataDocuments.AllowedClientIdPrefixes = ["https://trusted.example.com/"];
        _services.Origin.Serve(ClientId, Document);

        Assert.Null(await CreateClients().TryFindClientAsync(Tenant, ClientId));
        Assert.Empty(_services.Origin.Requests);
    }

    /// <summary>
    /// Section 10.1: the server "SHOULD reject a Client Identifier URL that is equal ... to its own issuer identifier,
    /// or to the identifier of any authorization server or resource server it has a trust relationship with".
    /// </summary>
    [Theory]
    [InlineData("https://issuer.example.com/")]
    [InlineData("https://api.example.com/orders")]
    [InlineData("https://trusted-issuer.example.com/jwt")]
    public async Task AUrlNamingAServerThisOneTrusts_IsUnknown_WithoutAFetch(string clientId)
    {
        _services.Options.JwtBearer.TrustedIssuers =
        [
            new TrustedIssuer
            {
                Issuer = "https://trusted-issuer.example.com/jwt",
                JwksUri = new Uri("https://trusted-issuer.example.com/jwks"),
            },
        ];
        _services.Origin.Serve(clientId, Document);

        Assert.Null(await CreateClients().TryFindClientAsync(Tenant, clientId));
        Assert.Empty(_services.Origin.Requests);
    }

    [Fact]
    public async Task AUrlWhoseDocumentCannotBeHad_IsUnknown()
    {
        Assert.Null(await CreateClients().TryFindClientAsync(Tenant, ClientId));
        Assert.Equal(1, _services.Origin.RequestsTo(ClientId));
    }
}
