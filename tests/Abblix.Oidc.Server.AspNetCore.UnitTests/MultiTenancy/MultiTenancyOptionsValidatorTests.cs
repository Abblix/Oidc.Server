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
    /// A Host header is ASCII, so a host with no ASCII form under IDN rules - here one carrying a zero-width
    /// joiner - could never be requested.
    /// </summary>
    [Fact]
    public void AnIssuerHostWithNoAsciiForm_IsRefused()
        => Assert.Contains("no ASCII form", FailureOf(Tenant("acme", "https://a\u200Db.example.com/")),
            StringComparison.Ordinal);

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
    [InlineData("https://auth.example.com/tenants/a%2fb", "https://auth.example.com/tenants/a%2Fb")]
    [InlineData("https://auth.example.com/tenants/a%20b", "https://auth.example.com/tenants/a b")]
    public void TwoIssuersAtOneAddress_AreRefused(string first, string second)
        => Assert.Contains("served at the same address", FailureOf(Tenant("acme", first), Tenant("globex", second)),
            StringComparison.Ordinal);

    /// <summary>
    /// A tenant's mutual-TLS address names only the host its aliases are served at: they keep the issuer's path, so
    /// a path of its own, plain http, a query or a fragment could not be honoured.
    /// </summary>
    [Theory]
    [InlineData("https://mtls.example.com/base")]
    [InlineData("http://mtls.example.com")]
    [InlineData("https://mtls.example.com/?x=1")]
    [InlineData("/mtls")]
    public void AMutualTlsAddressThatIsNotAnHttpsHost_IsRefused(string mtls)
        => Assert.Contains("must be an absolute https URL with no path", FailureOf(new TenantDefinition
        {
            Id = "acme",
            Issuer = "https://auth.example.com/tenants/acme",
            MtlsBaseUri = new Uri(mtls, UriKind.RelativeOrAbsolute),
        }), StringComparison.Ordinal);

    /// <summary>
    /// A tenant's mutual-TLS host under its issuer path is one of its addresses, so two tenants cannot reach one
    /// through it, whichever host the other's is.
    /// </summary>
    [Fact]
    public void AMutualTlsAddressAnotherTenantIsServedAt_IsRefused()
        => Assert.Contains("served at the same address mtls.example.com/tenants/acme", FailureOf(
            new TenantDefinition
            {
                Id = "acme",
                Issuer = "https://auth.example.com/tenants/acme",
                MtlsBaseUri = new Uri("https://mtls.example.com"),
            },
            new TenantDefinition { Id = "globex", Issuer = "https://mtls.example.com/tenants/acme" }),
            StringComparison.Ordinal);

    [Fact]
    public void TenantsSharingAMutualTlsHost_UnderPathsOfTheirOwn_AreAccepted()
        => Assert.Null(FailureOf(
            new TenantDefinition
            {
                Id = "acme",
                Issuer = "https://auth.example.com/tenants/acme",
                MtlsBaseUri = new Uri("https://mtls.example.com"),
            },
            new TenantDefinition
            {
                Id = "globex",
                Issuer = "https://auth.example.com/tenants/globex",
                MtlsBaseUri = new Uri("https://mtls.example.com"),
            }));

    /// <summary>
    /// Addresses differing in case of the path are two: a request's path is compared exactly.
    /// </summary>
    [Fact]
    public void IssuersDifferingInTheCaseOfTheirPaths_AreTwoAddresses()
        => Assert.Null(FailureOf(
            Tenant("acme", "https://auth.example.com/tenants/acme"),
            Tenant("globex", "https://auth.example.com/Tenants/acme")));
}
