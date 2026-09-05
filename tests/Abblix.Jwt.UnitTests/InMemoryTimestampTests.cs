// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A payload built in code holds the .NET primitive each claim was written as, and such a value
/// answers a typed read only for its own type. A token off the wire never has this shape, so the
/// suite that validates compact tokens cannot see a reader that stopped accepting one of them.
/// </summary>
public class InMemoryTimestampTests
{
    private static readonly DateTimeOffset Expected = DateTimeOffset.FromUnixTimeSeconds(1700000000);

    [Fact]
    public void AnIntegerLiteral_ReadsAsADate()
    {
        var payload = new JsonWebTokenPayload(new JsonObject { [JwtClaimTypes.IssuedAt] = 1700000000 });

        Assert.Equal(Expected, payload.IssuedAt);
    }

    [Fact]
    public void ALongLiteral_ReadsAsADate()
    {
        var payload = new JsonWebTokenPayload(new JsonObject { [JwtClaimTypes.IssuedAt] = 1700000000L });

        Assert.Equal(Expected, payload.IssuedAt);
    }

    [Fact]
    public void ADecimalLiteral_ReadsAsADateWithTheFractionDropped()
    {
        var payload = new JsonWebTokenPayload(new JsonObject { [JwtClaimTypes.IssuedAt] = 1700000000.5m });

        Assert.Equal(Expected, payload.IssuedAt);
    }

    /// <summary>
    /// The backings a list of primitives leaves off: a reader that names one type at a time reads
    /// none of these, and the one a consumer writes is the one the list forgot.
    /// </summary>
    [Fact]
    public void AnUnsignedIntegerLiteral_ReadsAsADate()
    {
        var payload = new JsonWebTokenPayload(new JsonObject { [JwtClaimTypes.IssuedAt] = 1700000000u });

        Assert.Equal(Expected, payload.IssuedAt);
    }

    [Fact]
    public void AnUnsignedLongLiteral_ReadsAsADate()
    {
        var payload = new JsonWebTokenPayload(new JsonObject { [JwtClaimTypes.IssuedAt] = 1700000000ul });

        Assert.Equal(Expected, payload.IssuedAt);
    }

    [Fact]
    public void AShortLiteral_ReadsAsADate()
    {
        var payload = new JsonWebTokenPayload(new JsonObject { [JwtClaimTypes.IssuedAt] = (short)1 });

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1), payload.IssuedAt);
    }

    [Fact]
    public void ADoubleLiteral_ReadsAsADateWithTheFractionDropped()
    {
        var payload = new JsonWebTokenPayload(new JsonObject { [JwtClaimTypes.IssuedAt] = 1700000000.5 });

        Assert.Equal(Expected, payload.IssuedAt);
    }
}
