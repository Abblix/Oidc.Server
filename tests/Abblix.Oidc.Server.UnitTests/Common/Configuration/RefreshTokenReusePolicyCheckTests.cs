// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant's client's refresh token reuse policy is checked when the tenant is read, rather than when the client is
/// first issued a refresh token.
/// </summary>
public class RefreshTokenReusePolicyCheckTests
{
    private static TenantDefinition TenantWith(params ClientInfo[] clients) => new()
    {
        Id = "acme",
        Issuer = TestConstants.DefaultIssuer,
        Clients = clients,
    };

    [Fact]
    public void AnUndefinedPolicy_IsRefused()
    {
        var tenant = TenantWith(
            new ClientInfo("web"),
            new ClientInfo("mobile") { RefreshToken = new RefreshTokenOptions { ReusePolicy = (RefreshTokenReusePolicy)42 } });

        var refusal = Assert.Single(new RefreshTokenReusePolicyCheck(NullLogger<RefreshTokenReusePolicyCheck>.Instance).Check([tenant], new OidcOptions()));

        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
    }

    /// <summary>
    /// The shipped composition refuses it too, which a check nobody registers would not.
    /// </summary>
    [Fact]
    public void TheComposition_RefusesAnUndefinedPolicy()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddOidcCore(options => options.Tenants.Add(TenantWith(
            new ClientInfo("web")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                RefreshToken = new RefreshTokenOptions { ReusePolicy = (RefreshTokenReusePolicy)42 },
            })));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains(refusal.Failures, failure => failure.Contains(nameof(RefreshTokenOptions.ReusePolicy)));
    }

    [Theory]
    [InlineData(RefreshTokenReusePolicy.WhenSenderConstrained)]
    [InlineData(RefreshTokenReusePolicy.Reuse)]
    [InlineData(RefreshTokenReusePolicy.Rotate)]
    public void ADefinedPolicy_PassesTheCheck(RefreshTokenReusePolicy policy)
    {
        var tenant = TenantWith(new ClientInfo("web") { RefreshToken = new RefreshTokenOptions { ReusePolicy = policy } });

        Assert.Empty(new RefreshTokenReusePolicyCheck(NullLogger<RefreshTokenReusePolicyCheck>.Instance).Check([tenant], new OidcOptions()));
    }

    /// <summary>
    /// Reuse declared for a public client that does not require DPoP is served, since its tokens bound to no key rotate
    /// at runtime (RFC 9700 section 2.2.2), and a warning names the tenant and the client.
    /// </summary>
    [Fact]
    public void Reuse_ForAPublicClientWithoutDPoP_IsServed_WithAWarning()
    {
        var log = new RecordingLoggerFactory();
        var tenant = TenantWith(
            new ClientInfo("web"),
            new ClientInfo("spa")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                RefreshToken = new RefreshTokenOptions { ReusePolicy = RefreshTokenReusePolicy.Reuse },
            });

        Assert.Empty(new RefreshTokenReusePolicyCheck(new Logger<RefreshTokenReusePolicyCheck>(log))
            .Check([tenant], new OidcOptions()));

        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogEvents.MultiTenancy.RefreshTokenReusePolicyCheck.ReuseNotFollowed, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal("acme", entry.Value("TenantId"));
        Assert.Equal("spa", entry.Value("ClientId"));
    }

    /// <summary>
    /// The settings are validated again for every request scope, and a store is read again every period, so a client
    /// is warned of once rather than at each check.
    /// </summary>
    [Fact]
    public void TheWarning_IsLoggedOncePerClient()
    {
        var log = new RecordingLoggerFactory();
        var check = new RefreshTokenReusePolicyCheck(new Logger<RefreshTokenReusePolicyCheck>(log));
        var tenant = TenantWith(new ClientInfo("spa")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            RefreshToken = new RefreshTokenOptions { ReusePolicy = RefreshTokenReusePolicy.Reuse },
        });

        _ = check.Check([tenant], new OidcOptions()).ToList();
        _ = check.Check([tenant], new OidcOptions()).ToList();

        Assert.Single(log.Entries);
    }

    /// <summary>
    /// A client is warned of by its tenant and its identifier together: two such clients of one tenant, and a client
    /// of another tenant with the same identifier, are each warned of.
    /// </summary>
    [Fact]
    public void TheWarning_IsLoggedForEachClientOfEachTenant()
    {
        var log = new RecordingLoggerFactory();
        static ClientInfo ReusingSpa(string clientId) => new(clientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            RefreshToken = new RefreshTokenOptions { ReusePolicy = RefreshTokenReusePolicy.Reuse },
        };
        var acme = TenantWith(ReusingSpa("spa"), ReusingSpa("mobile"));
        var globex = new TenantDefinition { Id = "globex", Issuer = TestConstants.DefaultIssuer, Clients = [ReusingSpa("spa")] };

        _ = new RefreshTokenReusePolicyCheck(new Logger<RefreshTokenReusePolicyCheck>(log))
            .Check([acme, globex], new OidcOptions())
            .ToList();

        Assert.Equal(
            ["acme/mobile", "acme/spa", "globex/spa"],
            log.Entries.Select(entry => $"{entry.Value("TenantId")}/{entry.Value("ClientId")}").Order().ToArray());
    }

    /// <summary>
    /// A client whose setting stopped calling for the warning and calls for it again is warned of again.
    /// </summary>
    [Fact]
    public void TheWarning_IsLoggedAgain_WhenTheSettingComesBack()
    {
        var log = new RecordingLoggerFactory();
        var check = new RefreshTokenReusePolicyCheck(new Logger<RefreshTokenReusePolicyCheck>(log));
        var reusing = new ClientInfo("spa")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            RefreshToken = new RefreshTokenOptions { ReusePolicy = RefreshTokenReusePolicy.Reuse },
        };
        var rotating = reusing with { RefreshToken = new RefreshTokenOptions { ReusePolicy = RefreshTokenReusePolicy.Rotate } };

        _ = check.Check([TenantWith(reusing)], new OidcOptions()).ToList();
        _ = check.Check([TenantWith(rotating)], new OidcOptions()).ToList();
        _ = check.Check([TenantWith(reusing)], new OidcOptions()).ToList();

        Assert.Equal(2, log.Entries.Count);
    }

    /// <summary>
    /// A public client on another policy is warned of by nothing: its policy says nothing a token rotating could
    /// contradict.
    /// </summary>
    [Theory]
    [InlineData(RefreshTokenReusePolicy.Rotate)]
    [InlineData(RefreshTokenReusePolicy.WhenSenderConstrained)]
    public void APublicClientOnAnotherPolicy_IsNotWarnedOf(RefreshTokenReusePolicy policy)
    {
        var log = new RecordingLoggerFactory();
        var tenant = TenantWith(new ClientInfo("spa")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            RefreshToken = new RefreshTokenOptions { ReusePolicy = policy },
        });

        _ = new RefreshTokenReusePolicyCheck(new Logger<RefreshTokenReusePolicyCheck>(log))
            .Check([tenant], new OidcOptions())
            .ToList();

        Assert.Empty(log.Entries);
    }

    /// <summary>
    /// The warning is logged exactly where a token the client is issued now rotates although it declares Reuse: a client
    /// requiring DPoP is issued tokens bound to its key, which it keeps reusing.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.None, false)]
    [InlineData(ClientAuthenticationMethods.None, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, false)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, true)]
    public void TheWarning_IsLoggedExactlyWhereATokenIssuedNowRotates(
        string tokenEndpointAuthMethod,
        bool requireDPoP)
    {
        var log = new RecordingLoggerFactory();
        var client = new ClientInfo("client")
        {
            TokenEndpointAuthMethod = tokenEndpointAuthMethod,
            RequireDPoP = requireDPoP,
            RefreshToken = new RefreshTokenOptions { ReusePolicy = RefreshTokenReusePolicy.Reuse },
        };
        var tenant = TenantWith(client);
        var issuedNow = new JsonWebTokenPayload(new JsonObject());
        if (requireDPoP)
            issuedNow.Confirmation = new JsonWebTokenConfirmation { JwkThumbprint = "the-dpop-key-thumbprint" };

        _ = new RefreshTokenReusePolicyCheck(new Logger<RefreshTokenReusePolicyCheck>(log))
            .Check([tenant], new OidcOptions())
            .ToList();

        Assert.Equal(RefreshTokenRotationPolicy.Rotates(tenant, client, issuedNow), log.Entries.Count == 1);
    }
}
