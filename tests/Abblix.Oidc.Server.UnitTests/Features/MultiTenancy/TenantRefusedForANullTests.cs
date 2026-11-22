// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc;
using HostApplication.Clients;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// A tenant refused for a null still claims what it can be compared by - its keys, its custodian key names - so a
/// tenant claiming the same beside it is refused for the conflict, while what the checks find wrong with the refused
/// tenant alone is not told, as the mending its null needs causes some of it.
/// </summary>
public class TenantRefusedForANullTests
{
    private const string A = "a";
    private const string B = "b";

    private static readonly RsaJsonWebKey Shared = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

    /// <summary>
    /// A key whose certificates hold a null still has a thumbprint, so a tenant declaring the same key beside it is
    /// refused, as beside the key whole.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AKeyHoldingANull_IsStillClaimed(bool certificatesHoldANull)
    {
        var key = certificatesHoldANull ? Shared with { Certificates = [null!] } : Shared;
        var a = Tenant(A, signingKeys: [key]);
        var b = Tenant(B, signingKeys: [Shared]);

        var refusals = Judge(InSettings, a, b);

        Assert.Empty(Judge(InSettings, b));
        Assert.Contains(refusals, refusal => refusal.TenantIds.Contains(B));
    }

    /// <summary>
    /// A tenant with no issuer still claims its keys.
    /// </summary>
    [Fact]
    public void ATenantWithNoIssuer_StillClaimsItsKeys()
    {
        var a = Tenant(A, signingKeys: [Shared]);
        a = new TenantDefinition { Id = a.Id, Issuer = null!, SigningKeys = a.SigningKeys };
        var b = Tenant(B, signingKeys: [Shared]);

        var refusals = Judge(InSettings, a, b);

        Assert.Contains(refusals, refusal => refusal.TenantIds.Contains(B));
    }

    /// <summary>
    /// Custodian keys whose algorithm is null still claim their names, so a tenant naming the same key is refused.
    /// </summary>
    [Fact]
    public void CustodianKeysHoldingANull_AreStillClaimed()
    {
        var a = Tenant(A, custodianKeys: new CustodianHeldKeys { SigningKeyName = "k", SigningAlgorithm = null! });
        var b = Tenant(B, custodianKeys: new CustodianHeldKeys { SigningKeyName = "k" });

        var refusals = Judge(InCustodian, a, b);

        Assert.Empty(Judge(InCustodian, b));
        Assert.Contains(refusals, refusal => refusal.TenantIds.Contains(B));
    }

    /// <summary>
    /// A tenant whose only signing key is null is told of the null, and not that it declares no signing key, which
    /// only the mending makes true.
    /// </summary>
    [Fact]
    public void ARefusedTenant_IsToldOfItsNullsAlone()
    {
        var a = Tenant(A, signingKeys: [null!]);

        var refusals = Judge(InSettings, a);

        var told = refusals.Where(refusal => refusal.TenantIds.Contains(A)).ToArray();
        Assert.Equal(TenantShape.NullsOf(a).Count(), told.Length);
    }

    /// <summary>
    /// A host's check refusing with no tenant named is told whatever else is refused.
    /// </summary>
    [Fact]
    public void ARefusalNamingNoTenant_IsTold()
    {
        var a = Tenant(A, signingKeys: [null!]);
        var anonymous = new TenantRefusal([], "the host's own refusal");
        var hostCheck = new Mock<ITenantsCheck>();
        hostCheck.Setup(check => check.Check(It.IsAny<IReadOnlyCollection<TenantDefinition>>(), It.IsAny<OidcOptions>()))
            .Returns([anonymous]);

        var refusals = TenantRefusal.AllOf([hostCheck.Object], [a], new OidcOptions()).ToArray();

        Assert.Contains(anonymous, refusals);
    }

    /// <summary>
    /// A host's client referring to itself is walked and mended once, refused for its null rather than overflowing
    /// the stack.
    /// </summary>
    [Fact]
    public void AClientReferringToItself_IsRefusedForItsNull()
    {
        var client = new HostClient("web") { ClientSecrets = [null!] };
        client.ActsFor = client;
        var a = new TenantDefinition
        {
            Id = A,
            Issuer = new Uri("https://a.example.com"),
            Clients = [client],
            SigningKeys = [Shared],
        };

        var refusals = Judge(InSettings, a);

        Assert.Contains("Clients['web'].ClientSecrets[0]", TenantShape.NullsOf(a));
        Assert.Contains(refusals, refusal => refusal.TenantIds.Contains(A));
    }

    private static TenantDefinition Tenant(
        string id,
        IReadOnlyCollection<JsonWebKey>? signingKeys = null,
        CustodianHeldKeys? custodianKeys = null)
        => new()
        {
            Id = id,
            Issuer = new Uri($"https://{id}.example.com"),
            SigningKeys = signingKeys ?? [],
            CustodianKeys = custodianKeys,
        };

    private static void InSettings(IServiceCollection services)
    {
        // The server reads each tenant's keys from its settings unless told otherwise
    }

    private static void InCustodian(IServiceCollection services)
    {
        services.AddSingleton(Mock.Of<IKeyCustodian>(custodian => custodian.ServesKeyManagement(It.IsAny<string>())));
        services.RequireKeyPlacement().UseKeysInCustodian();
    }

    private static TenantRefusal[] Judge(Action<IServiceCollection> keys, params TenantDefinition[] tenants)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddOidcServices(_ => { });
        keys(services);
        using var provider = services.BuildServiceProvider();
        return [..TenantRefusal.AllOf(provider.GetServices<ITenantsCheck>(), tenants, new OidcOptions())];
    }
}
