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
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

/// <summary>
/// Pins the single resource-normalization contract of <see cref="AuthorizationContext"/>: every
/// construction path funnels the RFC 8707 resource set through the primitive constructor, which
/// canonicalizes an empty set to <c>null</c> (an empty resource set means "no audience
/// restriction", same as a missing one).
/// </summary>
public class AuthorizationContextTests
{
    [Fact]
    public void Ctor_EmptyResources_CanonicalizedToNull()
    {
        var context = new AuthorizationContext("clientId", ["scope"], null, []);

        Assert.Null(context.Resources);
    }

    [Fact]
    public void Ctor_NonEmptyResources_Preserved()
    {
        var resources = new[] { new Uri("https://api.example.com/") };

        var context = new AuthorizationContext("clientId", ["scope"], null, resources);

        Assert.Equal(resources, context.Resources);
    }

    [Fact]
    public void Ctor_NullResources_StayNull()
    {
        var context = new AuthorizationContext("clientId", ["scope"], null);

        Assert.Null(context.Resources);
    }

    [Fact]
    public void RichCtor_EmptyResourceDefinitions_CanonicalizedToNull()
    {
        // The ScopeDefinition/ResourceDefinition overload forwards through the primitive ctor, so
        // the same empty -> null canonicalization applies to the authorize/CIBA/device path.
        var context = new AuthorizationContext(
            "clientId",
            Array.Empty<ScopeDefinition>(),
            Array.Empty<ResourceDefinition>(),
            null);

        Assert.Null(context.Resources);
    }
}
