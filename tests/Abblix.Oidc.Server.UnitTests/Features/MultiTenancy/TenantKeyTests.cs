// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// The key a store builds for an entity of a tenant, which keeps every tenant's entities apart in the one storage
/// they share.
/// </summary>
public class TenantKeyTests
{
    private static TenantDefinition Tenant(string id, string generation = "") => new()
    {
        Id = id,
        Issuer = new Uri("https://auth.example.com"),
        Generation = generation,
    };

    /// <summary>
    /// A key reads as the tenant's id, its generation when it has one, and the key, so an operator looking at the
    /// storage tells whose entry it is.
    /// </summary>
    [Theory]
    [InlineData("acme", "", "tenant:acme:code")]
    [InlineData("acme-eu_1", "", "tenant:acme-eu_1:code")]
    [InlineData("acme", "2f9c", "tenant:acme~2f9c:code")]
    public void AKey_NamesTheTenantAndItsGeneration(string id, string generation, string expected)
        => Assert.Equal(expected, TenantKey.Of(Tenant(id, generation), "code"));

    /// <summary>
    /// A tenant served by a catalog of the host's own passes none of the server's checks, so one whose id or
    /// generation could spell another tenant's space - tenant <c>a:b</c> with key <c>x</c> reading what tenant
    /// <c>a</c> wrote under <c>b:x</c> - builds no key at all.
    /// </summary>
    [Theory]
    [InlineData("a:b", "")]
    [InlineData("acme~2", "")]
    [InlineData("acme.eu", "")]
    [InlineData("acme eu", "")]
    [InlineData("münchen", "")]
    [InlineData("acme", "2:x")]
    [InlineData("acme", "2~x")]
    public void ATenantThatCannotNameItsSpace_BuildsNoKey(string id, string generation)
        => Assert.Throws<InvalidOperationException>(() => TenantKey.Of(Tenant(id, generation), "x"));

    /// <summary>
    /// A tenant created again under the id of one removed is another generation, and keys nothing the removed one
    /// stored: a code or a refresh token issued before the removal is not redeemed by whoever holds the id next.
    /// </summary>
    [Fact]
    public void ATenantCreatedAgainUnderAnId_KeysNothingTheFormerOneStored()
        => Assert.NotEqual(TenantKey.Of(Tenant("acme", "1"), "code"), TenantKey.Of(Tenant("acme", "2"), "code"));

    /// <summary>
    /// A generation must not run into the key of a tenant without one: tenant <c>acme</c> with key <c>4:code:x</c>
    /// and tenant <c>acme</c> of generation <c>code</c> with key <c>x</c> are two entries.
    /// </summary>
    [Fact]
    public void AGeneration_DoesNotRunIntoTheKeyOfATenantWithoutOne()
        => Assert.NotEqual(TenantKey.Of(Tenant("acme"), "4:code:x"), TenantKey.Of(Tenant("acme", "code"), "x"));
}
