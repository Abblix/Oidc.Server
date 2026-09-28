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

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The tenant lists startup refuses, each for the request it could not resolve or would resolve wrongly.
/// </summary>
public class MultiTenancyOptionsValidatorTests
{
    private static string? FailureOf(params TenantDefinition[] tenants)
    {
        var result = new MultiTenancyOptionsValidator().Validate(null, new MultiTenancyOptions { Tenants = [..tenants] });
        return result.Failed ? result.FailureMessage : null;
    }

    private static TenantDefinition Tenant(string id, string issuer) => new() { Id = id, Issuer = issuer };

    [Fact]
    public void TenantsAtTheirOwnHostsAndUnderPathsOfOneHost_AreAccepted()
        => Assert.Null(FailureOf(
            Tenant("acme", "https://acme.example.com"),
            Tenant("shared", "https://auth.example.com"),
            Tenant("globex", "https://auth.example.com/tenants/globex"),
            Tenant("globex-eu", "https://auth.example.com/tenants/globex/eu")));

    [Fact]
    public void ATenantWithNoId_IsRefused()
        => Assert.Contains("has no id", FailureOf(Tenant(string.Empty, "https://acme.example.com")),
            StringComparison.Ordinal);

    [Theory]
    [InlineData("acme.example.com")]
    [InlineData("/tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme?x=1")]
    [InlineData("https://auth.example.com/tenants/acme#x")]
    [InlineData("urn:acme")]
    [InlineData("file:///tenants/acme")]
    [InlineData("ftp://auth.example.com/tenants/acme")]
    public void AnIssuerThatIsNotAnHttpAddressWithoutQueryOrFragment_IsRefused(string issuer)
        => Assert.Contains("http or https URL", FailureOf(Tenant("acme", issuer)), StringComparison.Ordinal);

    /// <summary>
    /// Plain http stays open, since a server run locally for development is reached that way.
    /// </summary>
    [Fact]
    public void AnHttpIssuer_IsAccepted()
        => Assert.Null(FailureOf(Tenant("acme", "http://localhost:5000/tenants/acme")));

    [Fact]
    public void ATenantIdDeclaredTwice_IsRefused()
        => Assert.Contains("declared more than once", FailureOf(
            Tenant("acme", "https://acme.example.com"),
            Tenant("acme", "https://auth.example.com/tenants/acme")), StringComparison.Ordinal);

    /// <summary>
    /// A request is resolved by host and path alone, so two issuers equal on those would claim the same
    /// requests - and would accept each other's tokens at a relying party that compares them loosely.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/tenants/acme", "https://auth.example.com/tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme", "https://auth.example.com/tenants/acme/")]
    [InlineData("https://auth.example.com/tenants/acme", "https://AUTH.example.com/tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme", "https://auth.example.com./tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme", "http://auth.example.com/tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme", "https://auth.example.com:8443/tenants/acme")]
    [InlineData("https://münchen.example.com", "https://xn--mnchen-3ya.example.com")]
    public void TwoIssuersAtOneAddress_AreRefused(string first, string second)
        => Assert.Contains("served at the same address", FailureOf(Tenant("acme", first), Tenant("globex", second)),
            StringComparison.Ordinal);

    /// <summary>
    /// Addresses differing in case of the path are two: a request's path is compared exactly.
    /// </summary>
    [Fact]
    public void IssuersDifferingInTheCaseOfTheirPaths_AreTwoAddresses()
        => Assert.Null(FailureOf(
            Tenant("acme", "https://auth.example.com/tenants/acme"),
            Tenant("globex", "https://auth.example.com/Tenants/acme")));
}
