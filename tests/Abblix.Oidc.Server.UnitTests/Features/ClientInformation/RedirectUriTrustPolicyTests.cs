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
    /// untrusted, and one the settings or the host's store declare is trusted. With the token required, both are.
    /// </summary>
    [Theory]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    [InlineData(true, true, true)]
    public async Task ARegisteredClient_IsUntrustedWhileRegistrationIsOpen(
        bool requireInitialAccessToken, bool registered, bool trusted)
    {
        var client = new ClientInfo(ClientId);
        _registrations
            .Setup(store => store.TryFindRegisteredClientAsync(Tenant, ClientId))
            .ReturnsAsync(registered ? new RegisteredClient(client, "registration-token-id") : null);
        var options = new OidcOptions { RequireInitialAccessToken = requireInitialAccessToken };

        Assert.Equal(trusted, await Policy(options).IsTrustedAsync(Tenant, client));
    }

    private RedirectUriTrustPolicy Policy(OidcOptions options)
        => new(Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == options), _registrations.Object);
}
