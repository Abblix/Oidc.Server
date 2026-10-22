// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Pins when <see cref="TenantKeysCheck"/> refuses a tenant for having no signing key. The refusal must fire on
/// exactly one state - the library's own provider reading keys from each tenant's settings, and a tenant declaring
/// an empty <see cref="TenantDefinition.SigningKeys"/> - because that tenant can never sign a token and the fact is
/// fully known before the first request. Every other arrangement passes this check: a host-supplied provider may
/// read keys from a store that is legitimately unreachable while the host boots, and a half-wired custodian is
/// refused elsewhere with a message naming the missing placement call. The kind of key provider is read from the
/// real registration, so the check judges the provider a host gets.
/// </summary>
public class TenantKeysCheckTests
{
    /// <summary>
    /// The hopeless state: the settings' provider, no custodian, no keys. Without the refusal this tenant comes up
    /// healthy and publishes an empty JWKS for relying parties to cache.
    /// </summary>
    [Fact]
    public void Check_KeysFromSettingsWithoutASigningKey_Refuses()
    {
        using var serviceProvider = BuildHost();

        var refusal = Assert.Single(new TenantKeysCheck(serviceProvider).Check([Tenant()], new OidcOptions()));

        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains(nameof(TenantDefinition.SigningKeys), refusal.Message);
    }

    /// <summary>
    /// One declared key is enough: the settings' provider will serve it.
    /// </summary>
    [Fact]
    public void Check_KeysFromSettingsWithASigningKey_Passes()
    {
        using var serviceProvider = BuildHost();
        var tenant = Tenant(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature));

        Assert.Empty(new TenantKeysCheck(serviceProvider).Check([tenant], new OidcOptions()));
    }

    /// <summary>
    /// A host-supplied provider is trusted, not probed: its store may be unreachable during boot, and a startup
    /// probe would turn that into a refusal to start a working deployment.
    /// </summary>
    [Fact]
    public void Check_HostSuppliedProvider_PassesWithoutProbing()
    {
        var provider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);
        using var serviceProvider = BuildHost(services => services.AddSingleton(provider.Object));

        var refusals = new TenantKeysCheck(serviceProvider).Check([Tenant()], new OidcOptions()).ToList();

        Assert.Empty(refusals);
        provider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A registered custodian means external keys are intended; the placement machinery owns that path and refuses
    /// its misconfigurations with a more precise message than this check could.
    /// </summary>
    [Fact]
    public void Check_WithCustodianRegistered_LeavesTheDecisionToPlacement()
    {
        using var serviceProvider = BuildHost(services => services.AddSingleton(Mock.Of<IKeyCustodian>()));

        // No signing key and yet no refusal: with a custodian present the placement machinery, not this check, is
        // the authority on whether the arrangement is complete.
        Assert.Empty(new TenantKeysCheck(serviceProvider).Check([Tenant()], new OidcOptions()));
    }

    /// <summary>
    /// One key declared by two tenants, in either role and under any key id, is refused naming both.
    /// </summary>
    [Theory]
    [InlineData("globex", false, false)]
    [InlineData("globex", true, false)]
    [InlineData("globex", false, true)]
    public void Check_OneKeyDeclaredByTwoTenants_RefusesBoth(string otherId, bool otherKeyId, bool asEncryption)
    {
        using var serviceProvider = BuildHost();
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var copy = otherKeyId ? key with { KeyId = "another" } : key;
        var other = new TenantDefinition
        {
            Id = otherId,
            Issuer = new Uri("https://other.example.com"),
            SigningKeys = asEncryption ? [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)] : [copy],
            EncryptionKeys = asEncryption ? [copy] : [],
        };

        var refusal = Assert.Single(new TenantKeysCheck(serviceProvider).Check([Tenant(key), other], new OidcOptions()));

        Assert.Equal(["acme", otherId], refusal.TenantIds);
    }

    /// <summary>
    /// A tenant declaring one key twice, or in both roles, shares it with nobody.
    /// </summary>
    [Fact]
    public void Check_OneKeyDeclaredTwiceByOneTenant_Passes()
    {
        using var serviceProvider = BuildHost();
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var tenant = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            SigningKeys = [key, key],
            EncryptionKeys = [key],
        };

        Assert.Empty(new TenantKeysCheck(serviceProvider).Check([tenant], new OidcOptions()));
    }

    public static TheoryData<JsonWebKey, bool> KeysLackingAMemberTheirTypeRequires()
    {
        JsonWebKey[] keys =
        [
            new RsaJsonWebKey { KeyId = "incomplete", Exponent = [1, 0, 1] },
            new EllipticCurveJsonWebKey { KeyId = "incomplete", X = [1], Y = [2] },
            new OctetJsonWebKey { KeyId = "incomplete" },
        ];

        var rows = new TheoryData<JsonWebKey, bool>();
        foreach (var key in keys)
        {
            rows.Add(key, false);
            rows.Add(key, true);
        }

        return rows;
    }

    /// <summary>
    /// A key declared, to sign or to encrypt, without every member its key type requires refuses its own tenant and
    /// leaves the tenant beside it served, rather than failing the whole check.
    /// </summary>
    [Theory]
    [MemberData(nameof(KeysLackingAMemberTheirTypeRequires))]
    public void Check_AKeyLackingAMemberItsTypeRequires_RefusesItsTenantAlone(JsonWebKey incomplete, bool asEncryption)
    {
        using var serviceProvider = BuildHost();
        var broken = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            SigningKeys = asEncryption
                ? [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)]
                : [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature), incomplete],
            EncryptionKeys = asEncryption ? [incomplete] : [],
        };
        var served = new TenantDefinition
        {
            Id = "globex",
            Issuer = new Uri("https://other.example.com"),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        };

        var refusal = Assert.Single(new TenantKeysCheck(serviceProvider).Check([broken, served], new OidcOptions()));

        Assert.Equal(["acme"], refusal.TenantIds);
    }

    private static TenantDefinition Tenant(params JsonWebKey[] signingKeys) => new()
    {
        Id = "acme",
        Issuer = new Uri("https://auth.example.com"),
        SigningKeys = signingKeys,
    };

    /// <summary>
    /// Builds the service graph the way a host does: the real registration of the key provider, plus whatever the
    /// case under test adds. The host-supplied registration runs first, matching a host that registers its provider
    /// before calling the library.
    /// </summary>
    private static ServiceProvider BuildHost(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddSingleton(Mock.Of<IIssuerSettings>());
        configure?.Invoke(services);
        services.AddAuthServiceJwt();
        return services.BuildServiceProvider();
    }
}
