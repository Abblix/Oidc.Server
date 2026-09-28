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
    private static string? FailureOf(MultiTenancyOptions options)
    {
        var result = new MultiTenancyOptionsValidator().Validate(null, options);
        return result.Failed ? result.FailureMessage : null;
    }

    private static TenantDefinition Tenant(string id, string? issuer = null, params string[] hosts)
        => new() { Id = id, Issuer = issuer ?? $"https://auth.example.com/t/{id}", Hosts = hosts };

    [Fact]
    public void AValidTenantList_IsAccepted()
        => Assert.Null(FailureOf(new MultiTenancyOptions
        {
            Tenants = [Tenant("acme", "https://acme.example.com", "acme.example.com"), Tenant("globex")],
        }));

    /// <summary>
    /// An id travels as a path segment, so it holds only characters that travel unencoded, and not dots alone,
    /// which a server collapses before any routing sees them.
    /// </summary>
    [Theory]
    [InlineData("a/b")]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("a%20b")]
    [InlineData("a b")]
    [InlineData("a?b")]
    public void ATenantIdThatIsNotAPlainPathSegment_IsRefused(string tenantId)
        => Assert.Contains("URL-unreserved", FailureOf(new MultiTenancyOptions { Tenants = [Tenant(tenantId)] }),
            StringComparison.Ordinal);

    [Theory]
    [InlineData("")]
    [InlineData("t/x")]
    [InlineData("..")]
    public void APathSegmentThatIsNotAPlainPathSegment_IsRefused(string segment)
        => Assert.Contains(nameof(MultiTenancyOptions.PathSegment),
            FailureOf(new MultiTenancyOptions { PathSegment = segment }), StringComparison.Ordinal);

    [Theory]
    [InlineData("acme.example.com")]
    [InlineData("/t/acme")]
    [InlineData("https://auth.example.com/t/acme?x=1")]
    [InlineData("https://auth.example.com/t/acme#x")]
    public void AnIssuerThatIsNotAnAbsoluteUriWithoutQueryOrFragment_IsRefused(string issuer)
        => Assert.Contains("absolute URI", FailureOf(new MultiTenancyOptions { Tenants = [Tenant("acme", issuer)] }),
            StringComparison.Ordinal);

    /// <summary>
    /// Two tenants with one issuer would accept each other's tokens.
    /// </summary>
    [Fact]
    public void AnIssuerDeclaredByTwoTenants_IsRefused()
        => Assert.Contains("declared by more than one tenant", FailureOf(new MultiTenancyOptions
        {
            Tenants = [Tenant("acme", "https://auth.example.com"), Tenant("globex", "https://auth.example.com")],
        }), StringComparison.Ordinal);

    /// <summary>
    /// Issuers a relying party would take for one - differing by host case or a trailing slash - are one.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/t/acme", "https://auth.example.com/t/acme/")]
    [InlineData("https://auth.example.com/t/acme", "https://AUTH.example.com/t/acme")]
    public void IssuersThatAreOneForARelyingParty_AreRefused(string first, string second)
        => Assert.Contains("declared by more than one tenant", FailureOf(new MultiTenancyOptions
        {
            Tenants =
            [
                new TenantDefinition { Id = "acme", Issuer = first },
                new TenantDefinition { Id = "acme2", Issuer = second, Hosts = ["auth.example.com"] },
            ],
        }), StringComparison.Ordinal);

    /// <summary>
    /// OpenID Connect Discovery 1.0 section 4.3: the issuer is the address the discovery document was fetched
    /// from, so a host-bound tenant's issuer is on one of its hosts.
    /// </summary>
    [Fact]
    public void AnIssuerOffTheTenantsHosts_IsRefused()
        => Assert.Contains("not on any of its hosts", FailureOf(new MultiTenancyOptions
        {
            Tenants = [Tenant("acme", "https://auth.example.com/t/acme", "acme.example.com")],
        }), StringComparison.Ordinal);

    /// <summary>
    /// And a tenant reached by path has its issuer end in that path.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com")]
    [InlineData("https://auth.example.com/t/globex")]
    [InlineData("https://auth.example.com/tenants/acme")]
    public void APathTenantsIssuerNotEndingInItsPath_IsRefused(string issuer)
        => Assert.Contains("/t/acme", FailureOf(new MultiTenancyOptions { Tenants = [Tenant("acme", issuer)] }),
            StringComparison.Ordinal);

    [Fact]
    public void ATenantWithNoHosts_WhenPathResolutionIsOff_IsRefused()
        => Assert.Contains("no request can reach it", FailureOf(new MultiTenancyOptions
        {
            PathSegment = null,
            Tenants = [Tenant("acme")],
        }), StringComparison.Ordinal);

    [Fact]
    public void ATenantIdDeclaredTwice_IsRefused()
        => Assert.Contains("declared more than once", FailureOf(new MultiTenancyOptions
        {
            Tenants = [Tenant("acme"), Tenant("acme", "https://acme.example.com")],
        }), StringComparison.Ordinal);

    /// <summary>
    /// A request's host is compared without its port, so a binding written with one could never match.
    /// </summary>
    [Theory]
    [InlineData("acme.example.com:8443")]
    [InlineData("acme.example.com/path")]
    [InlineData("")]
    public void AHostThatIsNotAPlainHostName_IsRefused(string host)
        => Assert.Contains("without a port", FailureOf(new MultiTenancyOptions
        {
            Tenants = [Tenant("acme", "https://acme.example.com", host)],
        }), StringComparison.Ordinal);

    /// <summary>
    /// Host names are compared in one spelling, so two spellings of one host are one binding.
    /// </summary>
    [Theory]
    [InlineData("login.example.com", "Login.Example.com")]
    [InlineData("login.example.com", "login.example.com.")]
    [InlineData("münchen.example.com", "xn--mnchen-3ya.example.com")]
    public void AHostBoundToTwoTenants_IsRefused_WhateverItsSpelling(string first, string second)
        => Assert.Contains("bound to more than one tenant", FailureOf(new MultiTenancyOptions
        {
            Tenants = [Tenant("acme", "https://acme.example.com", first), Tenant("globex", null, second)],
        }), StringComparison.Ordinal);
}
