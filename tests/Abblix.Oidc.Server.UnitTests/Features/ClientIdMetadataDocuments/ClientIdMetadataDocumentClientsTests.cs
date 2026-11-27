// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Net.Http;
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

    public ClientIdMetadataDocumentClientsTests()
    {
        _store
            .Setup(store => store.FindClientAsync(It.IsAny<TenantDefinition>(), It.IsAny<string>()))
            .ReturnsAsync(ClientAbsence.Unknown);
    }

    private static readonly TenantDefinition Tenant = new()
    {
        Id = "tenant",
        // Under a path, so a client_id naming it passes the path rule and only the server rule refuses it; written in
        // mixed case with its default port, so the client_id that names it is its normalized spelling
        Issuer = new Uri("https://Issuer.Example.com:443/tenants/acme"),
        Resources = [new ResourceDefinition(new Uri("https://api.example.com/orders"))],
    };

    public void Dispose() => _services.Dispose();

    private ClientIdMetadataDocumentClients CreateClients() => new(
        _store.Object,
        NullLogger<ClientIdMetadataDocumentClients>.Instance,
        _services.Get<HeldMetadataDocuments>(),
        _services.Get<IServiceScopeFactory>(),
        _services.Get<IOptionsMonitor<OidcOptions>>(),
        new ProductionEnvironment(_services.Provider));

    /// <summary>
    /// Section 9.2: a server "MAY pre-register Client Identifier URLs", and a client so configured is served as
    /// configured, without a fetch.
    /// </summary>
    [Fact]
    public async Task AClientTheStoreKnows_IsServedFromTheStore_WithoutAFetch()
    {
        var stored = new ClientInfo(ClientId);
        _store.Setup(store => store.FindClientAsync(Tenant, ClientId)).ReturnsAsync(stored);
        _services.Origin.Serve(ClientId, Document);

        Assert.Same(stored, (await CreateClients().FindClientAsync(Tenant, ClientId)).GetSuccess());
        Assert.Empty(_services.Origin.Requests);
    }

    /// <summary>
    /// Section 3 compares Client Identifier URLs "using simple string comparison", so a client a store holds under
    /// another spelling of the URL is not the one the URL names, and the document is fetched.
    /// </summary>
    [Fact]
    public async Task AClientTheStoreHoldsUnderAnotherSpelling_IsNotServed_AndTheDocumentIsFetched()
    {
        var stored = new ClientInfo("HTTPS://client.example.com/metadata.json");
        _store.Setup(store => store.FindClientAsync(Tenant, ClientId)).ReturnsAsync(stored);
        _services.Origin.Serve(ClientId, Document);

        var answer = await CreateClients().FindClientAsync(Tenant, ClientId);

        Assert.False(answer.TryGetSuccess(out var found) && ReferenceEquals(found, stored));
        Assert.Equal(1, _services.Origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// An identifier not written as an https URL names no document, so its client is unknown like any other; one that
    /// is so written but is no client identifier URL (section 3) is a document the server refuses to fetch.
    /// </summary>
    [Theory]
    [InlineData("client-1", ClientAbsenceReason.Unknown)]
    [InlineData("http://client.example.com/metadata.json", ClientAbsenceReason.Unknown)]
    [InlineData("https://client.example.com/metadata.json?x=1", ClientAbsenceReason.Refused)]
    public async Task AnIdentifierThatIsNoClientIdentifierUrl_IsAbsent_WithoutAFetch(
        string clientId,
        ClientAbsenceReason reason)
    {
        _services.Origin.Serve(clientId, Document);

        Assert.Equal(reason, await AbsenceOf(clientId));
        Assert.Empty(_services.Origin.Requests);
    }

    [Fact]
    public async Task AUrlOutsideTheAllowList_IsRefused_WithoutAFetch()
    {
        _services.Options.ClientIdMetadataDocuments = _services.Options.ClientIdMetadataDocuments with { AllowedClientIdPrefixes = ["https://trusted.example.com/"] };
        _services.Origin.Serve(ClientId, Document);

        Assert.Equal(ClientAbsenceReason.Refused, await AbsenceOf(ClientId));
        Assert.Empty(_services.Origin.Requests);
    }

    /// <summary>
    /// Section 10.1: the server "SHOULD reject a Client Identifier URL that is equal ... to its own issuer identifier,
    /// or to the identifier of any authorization server or resource server it has a trust relationship with".
    /// </summary>
    [Theory]
    [InlineData("https://issuer.example.com/tenants/acme")]
    [InlineData("https://api.example.com/orders")]
    [InlineData("https://trusted-issuer.example.com/jwt")]
    public async Task AUrlNamingAServerThisOneTrusts_IsRefused_WithoutAFetch(string clientId)
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

        Assert.Equal(ClientAbsenceReason.Refused, await AbsenceOf(clientId));
        Assert.Empty(_services.Origin.Requests);
    }

    /// <summary>
    /// Section 6.1: a document that "could not be retrieved or was invalid" ends the lookup, and a failure is transient
    /// when it is "comparable in spirit to the temporarily_unavailable condition", as a server error or an unreachable
    /// host is; any other answer of the client's server refuses the document.
    /// </summary>
    [Theory]
    [InlineData(HttpStatusCode.NotFound, ClientAbsenceReason.Refused)]
    [InlineData(HttpStatusCode.ServiceUnavailable, ClientAbsenceReason.TemporarilyUnavailable)]
    public async Task AUrlWhoseDocumentCannotBeHad_IsAbsent_ForTheReasonItsServerGives(
        HttpStatusCode status,
        ClientAbsenceReason reason)
    {
        _services.Origin.Answer(ClientId, () => new HttpResponseMessage(status));

        Assert.Equal(reason, await AbsenceOf(ClientId));
        Assert.Equal(1, _services.Origin.RequestsTo(ClientId));
    }

    [Fact]
    public async Task AnUnreachableDocument_IsTemporarilyUnavailable()
    {
        _services.Origin.Unreachable(ClientId);

        Assert.Equal(ClientAbsenceReason.TemporarilyUnavailable, await AbsenceOf(ClientId));
    }

    /// <summary>
    /// A document read but refused by the tenant judging it is refused, as an invalid one is.
    /// </summary>
    [Fact]
    public async Task ADocumentTheTenantRefuses_IsRefused()
    {
        _services.Origin.Serve(
            ClientId, """{"client_id":"https://client.example.com/metadata.json","redirect_uris":["javascript:x"]}""");

        Assert.Equal(ClientAbsenceReason.Refused, await AbsenceOf(ClientId));
        Assert.Equal(1, _services.Origin.RequestsTo(ClientId));
    }

    private async Task<ClientAbsenceReason> AbsenceOf(string clientId)
        => (await CreateClients().FindClientAsync(Tenant, clientId)).GetFailure().Reason;
}
