// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ResourceIndicators;

/// <summary>
/// An access token carries the scopes of the resources it names, and the scopes no resource declares
/// (RFC 8707 section 2.2).
/// </summary>
public class ResourceScopesTests
{
    private static readonly Uri Orders = new("https://api.example.com/orders");
    private static readonly Uri Payments = new("https://api.example.com/payments");

    private static readonly ResourceDefinition[] Declared =
    [
        new(Orders, new ScopeDefinition("orders.read"), new ScopeDefinition("shared.read")),
        new(Payments, new ScopeDefinition("payments.read"), new ScopeDefinition("shared.read")),
    ];

    private static string[] Narrowed(Uri[] resources, params string[] scope)
        => new AuthorizationContext("client", scope, null, resources)
            .NarrowedToItsResources(new TestIssuer { Resources = Declared }.ToTenant())
            .Scope;

    /// <summary>
    /// A token naming one resource keeps that resource's scope and the scopes no resource declares, and loses the
    /// scope of the resource it does not name.
    /// </summary>
    [Fact]
    public void AScopeOfAResourceTheTokenDoesNotName_IsDropped()
        => Assert.Equal(
            ["openid", "orders.read"],
            Narrowed([Orders], "openid", "orders.read", "payments.read"));

    /// <summary>
    /// A token naming both resources keeps both resources' scopes.
    /// </summary>
    [Fact]
    public void ATokenNamingBothResources_KeepsTheScopesOfBoth()
        => Assert.Equal(
            ["orders.read", "payments.read"],
            Narrowed([Orders, Payments], "orders.read", "payments.read"));

    /// <summary>
    /// A scope two resources declare stays on a token naming either of them.
    /// </summary>
    [Fact]
    public void AScopeOfTwoResources_StaysOnATokenNamingOneOfThem()
        => Assert.Equal(["shared.read"], Narrowed([Payments], "shared.read"));

    /// <summary>
    /// A token naming no resource keeps only the scopes no resource declares.
    /// </summary>
    [Fact]
    public void ATokenNamingNoResource_KeepsOnlyTheScopesNoResourceDeclares()
        => Assert.Equal(["openid"], Narrowed([], "openid", "orders.read"));

    /// <summary>
    /// A token naming a resource as an audience (RFC 8693) rather than a resource keeps that resource's scope, while
    /// an audience that is no declared resource addresses none.
    /// </summary>
    [Theory]
    [InlineData("https://api.example.com/payments", true)]
    [InlineData("payments-api", false)]
    public void AnAudienceEqualToADeclaredResource_AddressesIt(string audience, bool kept)
    {
        var context = new AuthorizationContext("client", ["payments.read"], null) { Audiences = [audience] };

        var narrowed = context.NarrowedToItsResources(new TestIssuer { Resources = Declared }.ToTenant()).Scope;

        Assert.Equal(kept, narrowed.Contains("payments.read"));
    }

    /// <summary>
    /// A tenant declaring no resources leaves the scope as it is.
    /// </summary>
    [Fact]
    public void ATenantDeclaringNoResources_LeavesTheScopeAlone()
    {
        var context = new AuthorizationContext("client", ["orders.read"], null, [Orders]);

        Assert.Equal(["orders.read"], context.NarrowedToItsResources(SingleIssuer.Tenant).Scope);
    }
}
