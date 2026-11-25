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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// A client registered, a registration replaced and one removed are each recorded at Information under an event id of
/// its own, once the store holds the outcome, with the tenant, the client and what it may do; an operation the store
/// refused records nothing, and no secret or registration access token reaches a record.
/// </summary>
public sealed class ClientRegistrationsLogTests
{
    private const string ClientId = "client-1";
    private const string Secret = "the-client-secret";
    private const string RegistrationAccessToken = "the-registration-access-token";
    private static readonly Uri Resource = new("https://api.example.com");

    private readonly RecordingLoggerFactory _logs = new();

    private LogRecord[] Recorded(int eventId) => _logs.Entries.Where(entry => entry.EventId.Id == eventId).ToArray();

    private static ClientRegistrationRequest Metadata() => new()
    {
        ClientId = ClientId,
        RedirectUris = [new Uri("https://client.example.com/cb")],
        GrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
        Scope = [Scopes.OpenId],
        AllowedResources = [Resource],
    };

    private static void AssertNoSecretIn(LogRecord record)
    {
        foreach (var leaked in new[] { Secret, RegistrationAccessToken })
        {
            Assert.DoesNotContain(leaked, record.Message);
            Assert.DoesNotContain(record.State!, pair => pair.Value?.ToString()?.Contains(leaked) == true);
        }
    }

    private static void AssertWhatTheClientMayDo(LogRecord record)
    {
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(SingleIssuer.Tenant.Id, record.Value("TenantId"));
        Assert.Equal(ClientId, record.Value("ClientId")?.ToString());
        Assert.Equal(
            [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            Assert.IsType<Sanitized[]>(record.Value("GrantTypes")).Select(value => value.ToString()));
        Assert.Equal([Scopes.OpenId], Assert.IsType<Sanitized[]>(record.Value("Scope")).Select(value => value.ToString()));
        Assert.Equal([Resource], Assert.IsType<Uri[]>(record.Value("Resources")));
    }

    private RegisterClientRequestProcessor Registering(bool kept)
    {
        var clients = new Mock<IClientInfoManager>();
        clients.Setup(c => c.TryAddClientAsync(It.IsAny<TenantDefinition>(), It.IsAny<RegisteredClient>())).ReturnsAsync(kept);
        var credentials = new Mock<IClientCredentialFactory>();
        credentials
            .Setup(c => c.Create(It.IsAny<string>(), ClientId))
            .Returns(new ClientCredentials(ClientId, Secret, null, null));
        var tokens = new Mock<IRegistrationAccessTokenService>();
        tokens
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(),
                It.IsAny<string>()))
            .ReturnsAsync(RegistrationAccessToken);

        return new RegisterClientRequestProcessor(
            new Logger<RegisterClientRequestProcessor>(_logs),
            credentials.Object, clients.Object, TimeProvider.System, Mock.Of<ITokenIdGenerator>(), tokens.Object,
            new NewClientOptions { AllowedResources = [Resource] }, Mock.Of<IClientSecretEncryptor>(),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == new OidcOptions()));
    }

    [Fact]
    public async Task AClientRegistered_IsRecordedWithWhatItMayDo()
    {
        var result = await Registering(kept: true)
            .ProcessAsync(SingleIssuer.Tenant, new ValidClientRegistrationRequest(Metadata(), SectorIdentifier: null));
        Assert.True(result.TryGetSuccess(out _));

        var record = Assert.Single(Recorded(LogEvents.ClientInformation.ClientRegistrationsLog.ClientRegistered));
        AssertWhatTheClientMayDo(record);
        Assert.Equal(ClientTrust.Reviewed, record.Value("Trust"));
        AssertNoSecretIn(record);
    }

    [Fact]
    public async Task ARegistrationTheStoreDidNotKeep_IsNotRecordedAsRegistered()
    {
        await Registering(kept: false)
            .ProcessAsync(SingleIssuer.Tenant, new ValidClientRegistrationRequest(Metadata(), SectorIdentifier: null));

        Assert.Empty(Recorded(LogEvents.ClientInformation.ClientRegistrationsLog.ClientRegistered));
    }

    private UpdateClientRequestProcessor Updating(bool held)
    {
        var clients = new Mock<IClientInfoManager>();
        clients
            .Setup(c => c.TryUpdateClientAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<RegisteredClient>(), It.IsAny<RegisteredClient>()))
            .ReturnsAsync(held);
        var tokens = new Mock<IRegistrationAccessTokenService>();
        tokens
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(),
                It.IsAny<string>()))
            .ReturnsAsync(RegistrationAccessToken);

        return new UpdateClientRequestProcessor(
            new Logger<UpdateClientRequestProcessor>(_logs),
            clients.Object, tokens.Object, Mock.Of<ITokenIdGenerator>(), TimeProvider.System,
            new NewClientOptions(), Mock.Of<IClientSecretEncryptor>());
    }

    private static ValidUpdateClientRequest Update()
    {
        var metadata = Metadata();
        var existing = new RegisteredClient(new ClientInfo(ClientId) { Trust = ClientTrust.Reviewed }, "jti");
        return new ValidUpdateClientRequest(new UpdateClientRequest(new ClientRequest(), metadata), existing, metadata);
    }

    [Fact]
    public async Task ARegistrationReplaced_IsRecordedAsItNowStands()
    {
        var result = await Updating(held: true).ProcessAsync(SingleIssuer.Tenant, Update());
        Assert.True(result.TryGetSuccess(out _));

        var record = Assert.Single(Recorded(LogEvents.ClientInformation.ClientRegistrationsLog.ClientUpdated));
        AssertWhatTheClientMayDo(record);
        Assert.Equal(ClientTrust.Reviewed, record.Value("Trust"));
        AssertNoSecretIn(record);
    }

    [Fact]
    public async Task AnUpdateOfARegistrationNoLongerHeld_IsNotRecorded()
    {
        await Updating(held: false).ProcessAsync(SingleIssuer.Tenant, Update());

        Assert.Empty(Recorded(LogEvents.ClientInformation.ClientRegistrationsLog.ClientUpdated));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ARegistrationRemoved_IsRecordedOnlyWhenTheStoreRemovedIt(bool held)
    {
        var client = new RegisteredClient(new ClientInfo(ClientId), "jti");
        var clients = new Mock<IClientInfoManager>();
        clients.Setup(c => c.TryRemoveClientAsync(It.IsAny<TenantDefinition>(), client)).ReturnsAsync(held);
        var processor = new RemoveClientRequestProcessor(
            new Logger<RemoveClientRequestProcessor>(_logs), clients.Object, TimeProvider.System, SingleIssuer.LicensedCatalog);

        await processor.ProcessAsync(SingleIssuer.Tenant, new ValidClientRequest(new ClientRequest(), client));

        var records = Recorded(LogEvents.ClientInformation.ClientRegistrationsLog.ClientRemoved);
        if (!held)
        {
            Assert.Empty(records);
            return;
        }

        var record = Assert.Single(records);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(SingleIssuer.Tenant.Id, record.Value("TenantId"));
        Assert.Equal(ClientId, record.Value("ClientId")?.ToString());
    }
}
