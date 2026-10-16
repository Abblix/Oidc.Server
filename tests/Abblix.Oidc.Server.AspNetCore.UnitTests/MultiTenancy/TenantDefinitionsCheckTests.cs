// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The tenant lists startup refuses, each for the request it could not resolve or would resolve wrongly.
/// </summary>
public class TenantDefinitionsCheckTests
{
    private static string? FailureOf(params TenantDefinition[] tenants) => FailureOf(allowHttp: false, tenants);

    /// <summary>
    /// The refusals of the tenant list, judged as the server judges it: the tenants' own definitions, and each
    /// tenant's settings by the server's check of its issuer.
    /// </summary>
    private static string? FailureOf(bool allowHttp, params TenantDefinition[] tenants)
    {
        var settings = new TenantSettingsCheck(
            Options.Create(new OidcOptions { AllowHttpIssuer = allowHttp }),
            [new IssuerOptionsValidator()]);
        var result = new TenantListValidator([new TenantDefinitionsCheck(), settings])
            .Validate(null, new MultiTenancyOptions { Tenants = [..tenants] });
        return result.Failed ? result.FailureMessage : null;
    }

    private static TenantDefinition Tenant(string id, string issuer)
        => new() { Id = id, Issuer = new Uri(issuer, UriKind.RelativeOrAbsolute) };

    [Fact]
    public void TenantsAtTheirOwnHostsAndUnderPathsOfOneHost_AreAccepted()
        => Assert.Null(FailureOf(
            Tenant("acme", "https://acme.example.com"),
            Tenant("shared", "https://auth.example.com"),
            Tenant("globex", "https://auth.example.com/tenants/globex"),
            Tenant("globex-eu", "https://auth.example.com/tenants/globex/eu")));

    /// <summary>
    /// A tenant bound from configuration without an issuer, or read from a store that holds none, is refused by name
    /// rather than failing the whole list.
    /// </summary>
    [Fact]
    public void ATenantWithNoIssuer_IsRefused_AndTheOthersAreNot()
    {
        var refusals = new TenantDefinitionsCheck().Check(
        [
            new TenantDefinition { Id = "acme", Issuer = null! },
            new TenantDefinition { Id = string.Empty, Issuer = null! },
            Tenant("globex", "https://globex.example.com"),
        ]).ToArray();

        Assert.Contains(refusals, refusal => refusal.TenantIds.SequenceEqual(["acme"]));
        Assert.DoesNotContain(refusals, refusal => refusal.TenantIds.Contains("globex"));
    }

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
        => Assert.NotNull(FailureOf(allowHttp: true, Tenant("acme", issuer)));

    /// <summary>
    /// A Host header is ASCII, so a host with no ASCII form under IDN rules - here one carrying a zero-width
    /// joiner - could never be requested.
    /// </summary>
    [Fact]
    public void AnIssuerHostWithNoAsciiForm_IsRefused()
        => Assert.Contains("no ASCII form", FailureOf(Tenant("acme", "https://a\u200Db.example.com/")),
            StringComparison.Ordinal);

    /// <summary>
    /// An issuer is an https URL; plain http is let through only when the deployment allows it, for a server run
    /// locally for development.
    /// </summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void AnHttpIssuer_IsAccepted_OnlyWhenTheDeploymentAllowsIt(bool allowHttp, bool accepted)
        => Assert.Equal(accepted, FailureOf(allowHttp, Tenant("acme", "http://localhost:5000/tenants/acme")) is null);

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
    public void TwoIssuersAtOneAddress_AreRefused(string first, string second)
        => Assert.Contains("served at the same address",
            FailureOf(allowHttp: true, Tenant("acme", first), Tenant("globex", second)), StringComparison.Ordinal);

    /// <summary>
    /// An issuer whose path lies under another tenant's on the same host is refused: a browser sends the outer
    /// tenant's sign-in cookie to every path below it, so an end user signed in there would arrive at the inner
    /// tenant signed in.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com", "https://auth.example.com/tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme", "https://auth.example.com/tenants/acme/eu")]
    [InlineData("https://auth.example.com/tenants/acme/eu", "https://auth.example.com/tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme", "https://AUTH.example.com/tenants/acme/eu")]
    public void AnIssuerUnderAnothersPath_IsRefused(string first, string second)
        => Assert.Contains("lies under", FailureOf(Tenant("acme", first), Tenant("globex", second)),
            StringComparison.Ordinal);

    /// <summary>
    /// A path that merely begins with another's text is a sibling, not a path under it, and tenants on other hosts
    /// share no cookie whatever their paths.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/tenants/acme", "https://auth.example.com/tenants/acme2")]
    [InlineData("https://auth.example.com/tenants/acme", "https://other.example.com/tenants/acme/eu")]
    public void IssuersBesideEachOther_AreAccepted(string first, string second)
        => Assert.Null(FailureOf(Tenant("acme", first), Tenant("globex", second)));

    /// <summary>
    /// The store of tenants is read again every period by a timer, so a period it cannot keep is refused at
    /// startup.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(60)] // longer than the timer reading the store accepts
    public void ARefreshPeriodTheTimerCannotKeep_IsRefused(int days)
    {
        var result = new TenantListValidator([])
            .Validate(null, new MultiTenancyOptions { RefreshEvery = TimeSpan.FromDays(days) });

        Assert.Contains(nameof(MultiTenancyOptions.RefreshEvery), result.FailureMessage, StringComparison.Ordinal);
    }

    /// <summary>
    /// A refusal names the tenants it is about: a tenant's own mistake names that tenant alone, a conflict every
    /// party to it, so a list read from a store can leave out exactly those.
    /// </summary>
    [Fact]
    public void ARefusal_NamesTheTenantsItIsAbout()
    {
        var refusals = new TenantDefinitionsCheck().Check(
        [
            Tenant("acme", "https://auth.example.com/tenants/x"),
            Tenant("globex", "https://auth.example.com/tenants/x"),
            Tenant("initech", "https://init\u200Dech.example.com"),
            Tenant("umbrella", "https://umbrella.example.com"),
        ]).ToArray();

        Assert.Contains(refusals, refusal => refusal.TenantIds.SequenceEqual(["acme", "globex"]));
        Assert.Contains(refusals, refusal => refusal.TenantIds.SequenceEqual(["initech"]));
        Assert.DoesNotContain(refusals, refusal => refusal.TenantIds.Contains("umbrella"));
    }

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
            Issuer = new Uri("https://auth.example.com/tenants/acme"),
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
                Issuer = new Uri("https://auth.example.com/tenants/acme"),
                MtlsBaseUri = new Uri("https://mtls.example.com"),
            },
            new TenantDefinition { Id = "globex", Issuer = new Uri("https://mtls.example.com/tenants/acme") }),
            StringComparison.Ordinal);

    [Fact]
    public void TenantsSharingAMutualTlsHost_UnderPathsOfTheirOwn_AreAccepted()
        => Assert.Null(FailureOf(
            new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri("https://auth.example.com/tenants/acme"),
                MtlsBaseUri = new Uri("https://mtls.example.com"),
            },
            new TenantDefinition
            {
                Id = "globex",
                Issuer = new Uri("https://auth.example.com/tenants/globex"),
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
