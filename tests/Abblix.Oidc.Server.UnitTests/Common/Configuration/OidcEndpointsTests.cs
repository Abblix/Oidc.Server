// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Pins the composition of <see cref="OidcEndpoints.Base"/> - the default value of
/// <see cref="OidcOptions.EnabledEndpoints"/>. Base is the always-on interactive OIDC core plus PAR and
/// RP-initiated logout; the six niche or security-sensitive endpoints are opt-in and must stay out of it. Locking
/// the set here makes any accidental widening (e.g. adding a new flag to Base) a failing test rather than a
/// silent change to what a default server exposes.
/// </summary>
public class OidcEndpointsTests
{
    private const OidcEndpoints OptInEndpoints =
        OidcEndpoints.CheckSession | OidcEndpoints.Revocation | OidcEndpoints.Introspection |
        OidcEndpoints.RegisterClient | OidcEndpoints.BackChannelAuthentication | OidcEndpoints.DeviceAuthorization;

    [Fact]
    public void Base_is_the_always_on_core_set()
    {
        var alwaysOn = OidcEndpoints.Configuration | OidcEndpoints.Keys | OidcEndpoints.Authorize |
                       OidcEndpoints.Token | OidcEndpoints.UserInfo | OidcEndpoints.EndSession |
                       OidcEndpoints.PushedAuthorizationRequest;

        Assert.Equal(OidcEndpoints.Base, alwaysOn);
    }

    [Fact]
    public void Base_equals_All_minus_the_six_opt_in_endpoints()
    {
        Assert.Equal(OidcEndpoints.All & ~OptInEndpoints, OidcEndpoints.Base);
    }

    [Theory]
    [InlineData(OidcEndpoints.CheckSession)]
    [InlineData(OidcEndpoints.Revocation)]
    [InlineData(OidcEndpoints.Introspection)]
    [InlineData(OidcEndpoints.RegisterClient)]
    [InlineData(OidcEndpoints.BackChannelAuthentication)]
    [InlineData(OidcEndpoints.DeviceAuthorization)]
    public void Base_excludes_every_opt_in_endpoint(OidcEndpoints optIn)
    {
        Assert.False(OidcEndpoints.Base.HasFlag(optIn));
    }

    [Fact]
    public void EnabledEndpoints_defaults_to_Base()
    {
        Assert.Equal(OidcEndpoints.Base, new OidcOptions().EnabledEndpoints);
    }
}
