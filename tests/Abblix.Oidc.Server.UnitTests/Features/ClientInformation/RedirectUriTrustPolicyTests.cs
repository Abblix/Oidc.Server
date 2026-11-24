// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// The default decision of RFC 9700 section 4.11.2: a client nobody reviewed is untrusted, every other one trusted.
/// </summary>
public sealed class RedirectUriTrustPolicyTests
{
    private const string ClientId = "https://client.example.com/metadata.json";

    private static readonly TenantDefinition Tenant = new TestIssuer().ToTenant();

    private readonly Mock<IClientInfoManager> _registrations = new(MockBehavior.Strict);

    private readonly Mock<IClientInfoProvider> _clients = new(MockBehavior.Strict);

    /// <summary>
    /// A client from its metadata document is trusted only under a list of allowed prefixes, the host's own assessment
    /// of the URLs it serves; with none, or an empty one, any URL may name itself a client.
    /// </summary>
    [Theory]
    [InlineData(null, false)]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "https://client.example.com/" }, true)]
    public async Task AClientFromItsMetadataDocument_IsTrustedOnlyUnderAPrefixList(string[]? prefixes, bool trusted)
    {
        var options = new OidcOptions { ClientIdMetadataDocuments = { AllowedClientIdPrefixes = prefixes } };
        var client = new ClientInfo(ClientId) { ResolvedFromMetadataDocument = true };

        Assert.Equal(trusted, await Policy(options).IsTrustedAsync(Tenant, client));
    }

    /// <summary>
    /// While registration needs no initial access token anybody may register a client, so a registered client is
    /// untrusted, and one the host's store still supplies is trusted. A client neither registered nor supplied any more,
    /// as a registration removed while the request was answered leaves it, is untrusted. With the token required, every
    /// client is trusted.
    /// </summary>
    [Theory]
    [InlineData(false, true, true, false)]
    [InlineData(false, false, true, true)]
    [InlineData(false, false, false, false)]
    [InlineData(true, true, true, true)]
    public async Task ARegisteredClient_IsUntrustedWhileRegistrationIsOpen(
        bool requireInitialAccessToken, bool registered, bool stillSupplied, bool trusted)
    {
        var client = new ClientInfo(ClientId);
        _registrations
            .Setup(store => store.TryFindRegisteredClientAsync(Tenant, ClientId))
            .ReturnsAsync(registered ? new RegisteredClient(client, "registration-token-id") : null);
        _clients
            .Setup(store => store.FindClientAsync(Tenant, ClientId))
            .ReturnsAsync(stillSupplied ? client : ClientAbsence.Unknown);
        var options = new OidcOptions { RequireInitialAccessToken = requireInitialAccessToken };

        Assert.Equal(trusted, await Policy(options).IsTrustedAsync(Tenant, client));
    }

    /// <summary>
    /// A store that cannot answer whether it still supplies the client, unavailable or refusing, supplies nothing to
    /// trust: the client is untrusted while registration is open.
    /// </summary>
    [Theory]
    [InlineData(ClientAbsenceReason.TemporarilyUnavailable)]
    [InlineData(ClientAbsenceReason.Refused)]
    public async Task AClientTheStoreCannotAnswerFor_IsUntrustedWhileRegistrationIsOpen(ClientAbsenceReason reason)
    {
        var client = new ClientInfo(ClientId);
        _registrations
            .Setup(store => store.TryFindRegisteredClientAsync(Tenant, ClientId))
            .ReturnsAsync((RegisteredClient?)null);
        _clients
            .Setup(store => store.FindClientAsync(Tenant, ClientId))
            .ReturnsAsync(new ClientAbsence(reason));

        Assert.False(await Policy(new OidcOptions { RequireInitialAccessToken = false }).IsTrustedAsync(Tenant, client));
    }

    /// <summary>
    /// A client the tenant settings declare is trusted with registration open, and no store is asked about it.
    /// </summary>
    [Fact]
    public async Task AClientTheSettingsDeclare_IsTrustedWhileRegistrationIsOpen()
    {
        var client = new ClientInfo(ClientId);
        var tenant = new TestIssuer { Clients = [client] }.ToTenant();

        Assert.True(await Policy(new OidcOptions { RequireInitialAccessToken = false }).IsTrustedAsync(tenant, client));
        _registrations.VerifyNoOtherCalls();
        _clients.VerifyNoOtherCalls();
    }

    private RedirectUriTrustPolicy Policy(OidcOptions options)
        => new(
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == options),
            _registrations.Object,
            _clients.Object);
}
