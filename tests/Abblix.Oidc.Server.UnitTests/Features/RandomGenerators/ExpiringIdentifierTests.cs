// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.RandomGenerators;

/// <summary>
/// An identifier a client polls with - a device code, an auth_req_id - carrying the instant it expires.
/// </summary>
public class ExpiringIdentifierTests
{
    private static readonly DateTimeOffset ExpiresAt = new(2026, 9, 29, 12, 30, 15, TimeSpan.Zero);

    [Fact]
    public void TheInstantAnIdentifierExpires_IsReadBackFromIt()
    {
        var identifier = ExpiringIdentifier.Compose("random-part", ExpiresAt);

        Assert.True(ExpiringIdentifier.TryReadExpiry(identifier, out var expiresAt));
        Assert.Equal(ExpiresAt, expiresAt);
        Assert.StartsWith("random-part", identifier, StringComparison.Ordinal);
    }

    /// <summary>
    /// An identifier made some other way - by a host's own generator, or before identifiers carried the instant -
    /// states no expiry, and so reads as unknown.
    /// </summary>
    [Theory]
    [InlineData("a-device-code-this-server-never-issued")]
    [InlineData("random-part.")]
    [InlineData("random-part.not!base64")]
    [InlineData("random-part.AAAA")]
    [InlineData("random-part.f_________8")] // the largest instant eight bytes hold, past any date
    [InlineData("random-part.gAAAAAAAAAA")] // the smallest, before any date
    [InlineData("")]
    public void AnIdentifierNotCarryingAnInstant_StatesNoExpiry(string identifier)
        => Assert.False(ExpiringIdentifier.TryReadExpiry(identifier, out _));
}
