// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Pins the property that lets a host keep its scope registry in configuration: every entry binds,
/// whatever its claim list looks like. The configuration binder constructs a positional record
/// through its constructor and silently drops an element whose collection parameter is absent or
/// empty from the source, so this only holds while <see cref="ScopeDefinition"/> exposes a
/// parameterless constructor with settable properties.
/// </summary>
public class ScopeDefinitionBindingTests
{
    /// <summary>
    /// A scope with claims, a scope with an explicitly empty claim list, and a scope that does not
    /// mention claims at all must each survive binding. The last two are the common shape of an
    /// API scope, which authorizes access to a resource and has nothing to say about the user.
    /// </summary>
    [Fact]
    public void Bind_ScopeWithoutClaimTypes_IsNotDropped()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Scopes:0:Scope"] = "orders",
                ["Scopes:0:ClaimTypes:0"] = "address_city",
                ["Scopes:1:Scope"] = "basket",
                // Scopes:1:ClaimTypes deliberately absent
                ["Scopes:2:Scope"] = "webhooks",
                ["Scopes:2:ClaimTypes"] = "",
            })
            .Build();

        var scopes = configuration.GetSection("Scopes").Get<ScopeDefinition[]>();

        Assert.NotNull(scopes);
        Assert.Collection(
            scopes,
            orders =>
            {
                Assert.Equal("orders", orders.Scope);
                Assert.Equal(["address_city"], orders.ClaimTypes);
            },
            basket =>
            {
                Assert.Equal("basket", basket.Scope);
                Assert.Empty(basket.ClaimTypes);
            },
            webhooks =>
            {
                Assert.Equal("webhooks", webhooks.Scope);
                Assert.Empty(webhooks.ClaimTypes);
            });
    }

    /// <summary>
    /// The positional constructor and deconstruction stay available: every existing call site
    /// builds a definition as <c>new("scope", "claim")</c>, and the shape must keep compiling.
    /// </summary>
    [Fact]
    public void PositionalConstruction_AndDeconstruction_KeepWorking()
    {
        var (scope, claimTypes) = new ScopeDefinition("orders", "address_city", "last_name");

        Assert.Equal("orders", scope);
        Assert.Equal(["address_city", "last_name"], claimTypes);
    }
}
