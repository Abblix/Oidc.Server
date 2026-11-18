// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DPoP;

/// <summary>
/// RFC 9449 section 7.1: a resource's DPoP challenge names the algorithms it accepts (<c>algs</c>), and under a
/// profile those are only the ones it admits (FAPI 1.0 Part 2 section 8.6, FAPI 2.0 section 5.4.1).
/// </summary>
public class DPoPAlgorithmsTests
{
    /// <summary>
    /// A refusal naming the algorithms of the client's profile is advertised with them, whatever the tenant's profile.
    /// </summary>
    [Fact]
    public void ARefusalNamingTheClientsAlgorithms_IsAdvertisedWithThem()
    {
        var error = new InvalidDPoPProofError("refused") { DPoPAlgorithmsAdmitted = [SigningAlgorithms.ES256] };

        Assert.Equal([SigningAlgorithms.ES256], DPoPAlgorithms.Advertised(error, SingleIssuer.Tenant));
    }

    /// <summary>
    /// Any other refusal is advertised with what the tenant's profile admits: only PS256 and ES256 at a tenant held to
    /// FAPI 2.0, none at one held to FAPI 1.0 Advanced, whose profile refuses DPoP (Part 2 section 8.2), and every
    /// algorithm DPoP admits at one held to none.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, new[] { SigningAlgorithms.ES256, SigningAlgorithms.PS256 })]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, new string[0])]
    [InlineData(ClientSecurityProfile.None, null)]
    public void AnyOtherRefusal_IsAdvertisedWithTheTenantsAlgorithms(ClientSecurityProfile profile, string[]? expected)
    {
        var tenant = new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

        var advertised = DPoPAlgorithms.Advertised(new OidcError(ErrorCodes.InvalidToken, "refused"), tenant);

        Assert.Equal(
            expected ?? DPoPAlgorithms.Allowed.Order(StringComparer.Ordinal).ToArray(),
            advertised.Order(StringComparer.Ordinal).ToArray());
    }
}
