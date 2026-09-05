// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.Licensing;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// The licence is verified without lifetime handling, so the loader is the first reader of its
/// timestamps - and a licence minted with one no date can hold failed the host at startup with
/// the accessor's own exception rather than the message every other licence fault produces.
/// </summary>
/// <remarks>
/// Driven through the read alone: verification needs a licence signed with the licensing key,
/// which no test holds, and the read is what changed.
/// </remarks>
public class LicenseReadingTests
{
    [Theory]
    [InlineData("exp")]
    [InlineData("nbf")]
    [InlineData("grace_period")]
    public void ATimestampNoDateCanHold_IsRefusedAsALicenceFaultNamingTheClaim(string claim)
    {
        var payload = new JsonWebTokenPayload(new JsonObject
        {
            ["valid_issuers"] = new JsonArray("https://auth.example.com"),
            [claim] = 99999999999999L,
        });

        var fault = Assert.Throws<InvalidOperationException>(() => LicenseLoader.ReadLicense(payload));

        Assert.StartsWith("The license can't be validated", fault.Message, StringComparison.Ordinal);
        Assert.Contains(claim, fault.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AReadableLicence_IsRead()
    {
        var expiresAt = new DateTimeOffset(2126, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var payload = new JsonWebTokenPayload(new JsonObject
        {
            ["valid_issuers"] = new JsonArray("https://auth.example.com"),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["issuer_limit"] = 1,
        });

        var license = LicenseLoader.ReadLicense(payload);

        Assert.Equal(expiresAt, license.ExpiresAt);
        Assert.Equal(1, license.IssuerLimit);
    }
}
