// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// A registration (RFC 7591) answers with what the store now holds, so one the store did not keep - raced by another
/// under the same id, or under an id the settings came to configure - is refused as a taken id is, and answers
/// with no credentials.
/// </summary>
public class RegisterClientRequestProcessorTests
{
    private readonly Mock<IClientInfoManager> _clients = new(MockBehavior.Strict);
    private readonly Mock<IRegistrationAccessTokenService> _tokens = new(MockBehavior.Loose);
    private readonly CapturingLogger<RegisterClientRequestProcessor> _logger = new();

    private RegisterClientRequestProcessor Processor() => Processor(_clients.Object);

    private RegisterClientRequestProcessor Processor(IClientInfoManager clients, NewClientOptions? newClients = null)
    {
        var credentials = new Mock<IClientCredentialFactory>(MockBehavior.Strict);
        credentials
            .Setup(c => c.Create(It.IsAny<string>(), "client-1"))
            .Returns(new ClientCredentials("client-1", "secret", null, null));

        var tokenIds = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIds.Setup(g => g.GenerateTokenId()).Returns("jti-1");

        _tokens
            .Setup(s => s.IssueTokenAsync(
                TestTenant.Matched,
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");

        return new RegisterClientRequestProcessor(
            _logger,
            credentials.Object, clients, TimeProvider.System, tokenIds.Object, _tokens.Object,
            newClients ?? new NewClientOptions());
    }

    private static ValidClientRegistrationRequest Request() => new(
        new ClientRegistrationRequest
        {
            ClientId = "client-1",
            RedirectUris = [new Uri("https://client.example.com/cb")],
        },
        SectorIdentifier: null);

    [Fact]
    public async Task ARegistrationTheStoreKeeps_IsAnsweredWithItsToken()
    {
        _clients
            .Setup(c => c.TryAddClientAsync(TestTenant.Matched, It.Is<RegisteredClient>(r =>
                r.ClientInfo.ClientId == "client-1" && r.RegistrationAccessTokenId == "jti-1")))
            .ReturnsAsync(true);

        var result = await Processor().ProcessAsync(SingleIssuer.Tenant, Request());

        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal("client-1", response.ClientId);
        _tokens.Verify(
            s => s.IssueTokenAsync(TestTenant.Matched, "client-1", It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), "jti-1"),
            Times.Once);
    }

    /// <summary>
    /// A client registering without a scope member may request the default set the host names, RFC 7591 section 2,
    /// and the registration is answered with that set; one naming its scope keeps the one it named.
    /// </summary>
    [Theory]
    [InlineData(null, "read")]
    [InlineData("write", "write")]
    public async Task AClientRegisteringWithoutScope_MayRequestTheHostsDefaultSet(string? named, string allowed)
    {
        RegisteredClient? stored = null;
        _clients
            .Setup(c => c.TryAddClientAsync(TestTenant.Matched, It.IsAny<RegisteredClient>()))
            .Callback((TenantDefinition _, RegisteredClient client) => stored = client)
            .ReturnsAsync(true);
        var request = new ValidClientRegistrationRequest(
            new ClientRegistrationRequest
            {
                ClientId = "client-1",
                RedirectUris = [new Uri("https://client.example.com/cb")],
                Scope = named is null ? null : [named],
            },
            SectorIdentifier: null);

        var result = await Processor(_clients.Object, new NewClientOptions { Scope = ["read"] })
            .ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal((string[])[allowed], stored!.ClientInfo.AllowedScopes);
        Assert.Equal((string[])[allowed], response.Metadata.Scope);
    }

    /// <summary>
    /// A registered client takes the assertion audiences the host grants new clients, since registration metadata has
    /// no member for them, and a tenant held to FAPI 2.0 gives it the issuer alone whatever the host grants.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, ClientAssertionAudiences.Issuer, ClientAssertionAudiences.Issuer)]
    [InlineData(ClientSecurityProfile.None, ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint, ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint)]
    [InlineData(ClientSecurityProfile.Fapi2, ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint | ClientAssertionAudiences.AllowArray, ClientAssertionAudiences.Issuer)]
    public async Task ARegisteredClient_TakesTheAssertionAudiencesTheHostGrantsNewClients(
        ClientSecurityProfile profile, ClientAssertionAudiences granted, ClientAssertionAudiences taken)
    {
        RegisteredClient? stored = null;
        _clients
            .Setup(c => c.TryAddClientAsync(TestTenant.Matched, It.IsAny<RegisteredClient>()))
            .Callback((TenantDefinition _, RegisteredClient client) => stored = client)
            .ReturnsAsync(true);
        var tenant = new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

        var result = await Processor(_clients.Object, new NewClientOptions { ClientAssertionAudiences = granted })
            .ProcessAsync(tenant, Request());

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(taken, stored!.ClientInfo.ClientAssertionAudiences);
    }

    /// <summary>
    /// A registration naming no signature algorithm for its ID tokens or JWT authorization responses keeps the RS256
    /// of OpenID Connect Dynamic Client Registration section 2 where no profile bounds them, and is given PS256 at a
    /// tenant held to FAPI 1.0 Advanced, whose Part 2 section 8.6 names only PS256 and ES256; the answer states it.
    /// One naming its own keeps it.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, null, SigningAlgorithms.RS256)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, null, SigningAlgorithms.PS256)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, SigningAlgorithms.ES256, SigningAlgorithms.ES256)]
    public async Task ARegistrationNamingNoAlgorithm_TakesOneItsProfileAdmits(
        ClientSecurityProfile profile, string? named, string taken)
    {
        RegisteredClient? stored = null;
        _clients
            .Setup(c => c.TryAddClientAsync(TestTenant.Matched, It.IsAny<RegisteredClient>()))
            .Callback((TenantDefinition _, RegisteredClient client) => stored = client)
            .ReturnsAsync(true);
        var request = new ValidClientRegistrationRequest(
            new ClientRegistrationRequest
            {
                ClientId = "client-1",
                RedirectUris = [new Uri("https://client.example.com/cb")],
                IdTokenSignedResponseAlg = named,
                AuthorizationSignedResponseAlg = named,
            },
            SectorIdentifier: null);
        var tenant = new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

        var result = await Processor().ProcessAsync(tenant, request);

        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal(taken, stored!.ClientInfo.IdentityTokenSignedResponseAlgorithm);
        Assert.Equal(taken, stored.ClientInfo.AuthorizationSignedResponseAlgorithm);
        Assert.Equal(taken, response.Metadata.IdTokenSignedResponseAlg);
    }

    /// <summary>
    /// A registered client takes the host's grant of offline access beside an access token carried through the user
    /// agent, which registration metadata has no member for.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARegisteredClient_TakesTheHostsGrantOfOfflineAccessBesideAUserAgentAccessToken(bool granted)
    {
        RegisteredClient? stored = null;
        _clients
            .Setup(c => c.TryAddClientAsync(TestTenant.Matched, It.IsAny<RegisteredClient>()))
            .Callback((TenantDefinition _, RegisteredClient client) => stored = client)
            .ReturnsAsync(true);

        await Processor(_clients.Object, new NewClientOptions { AllowOfflineAccessWithUserAgentAccessToken = granted })
            .ProcessAsync(SingleIssuer.Tenant, Request());

        Assert.Equal(granted, stored!.ClientInfo.AllowOfflineAccessWithUserAgentAccessToken);
    }

    [Fact]
    public async Task ARegistrationTheStoreDoesNotKeep_IsRefused()
    {
        _clients.Setup(c => c.TryAddClientAsync(TestTenant.Matched, It.IsAny<RegisteredClient>())).ReturnsAsync(false);

        var result = await Processor().ProcessAsync(SingleIssuer.Tenant, Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        var entry = Assert.Single(_logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(LogEvents.DynamicClientManagement.RegisterClientRequestProcessor.RegistrationNotKept, entry.EventId.Id);
    }

    /// <summary>
    /// A token that cannot be issued leaves nothing stored: the client id stays free for the registrant to retry.
    /// </summary>
    [Fact]
    public async Task ATokenThatCannotBeIssued_LeavesNoClientStored()
    {
        var processor = Processor();
        _tokens
            .Setup(s => s.IssueTokenAsync(
                TestTenant.Matched,
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("no signing key"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => processor.ProcessAsync(SingleIssuer.Tenant, Request()));

        _clients.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Against a real store, the second of two registrations under one id is refused, and the first is what is kept.
    /// </summary>
    [Fact]
    public async Task TheSecondOfTwoRegistrationsUnderOneId_IsRefusedByTheStore()
    {
        var store = new ReloadableClientInfoStorage(
            NullLogger<ReloadableClientInfoStorage>.Instance,
            SingleIssuer.Catalog,
            SingleIssuer.LocalOf<Dictionary<string, ClientInfo>>(),
            new IssuerClientRegistrations(
                SingleIssuer.LocalOf<ConcurrentDictionary<string, RegisteredClient>>()));
        var processor = Processor(store);

        Assert.True((await processor.ProcessAsync(SingleIssuer.Tenant, Request())).TryGetSuccess(out _));
        Assert.True((await processor.ProcessAsync(SingleIssuer.Tenant, Request())).TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.NotNull(await store.TryFindRegisteredClientAsync(SingleIssuer.Tenant, "client-1"));
    }

    /// <summary>
    /// Records the level and event of each entry.
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, EventId EventId)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId));
    }
}
