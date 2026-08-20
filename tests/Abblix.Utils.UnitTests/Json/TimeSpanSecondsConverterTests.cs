// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests.Json;

/// <summary>
/// The converter behind every duration this library puts on the wire as a count of seconds: <c>expires_in</c>
/// (RFC 6749 section 4.2.2), the CIBA <c>requested_expiry</c>, and the client-metadata lifetimes.
/// </summary>
/// <remarks>
/// Both token shapes are exercised because both actually arrive. A JSON number is what a well-behaved client
/// sends; a quoted number is what an HTML form produces, and the form-encoded endpoints of this library feed
/// that straight into the same converter. A test that only covered the number would leave the shape most
/// requests take on the token endpoint unexercised.
/// </remarks>
public class TimeSpanSecondsConverterTests
{
    private static readonly JsonSerializerOptions Options =
        new() { Converters = { new TimeSpanSecondsConverter() } };

    [Theory]
    [InlineData("3600", 3600)]
    [InlineData("0", 0)]
    [InlineData("86400", 86400)]
    public void Read_ANumber_IsSeconds(string json, int expected)
        => Assert.Equal(TimeSpan.FromSeconds(expected), JsonSerializer.Deserialize<TimeSpan>(json, Options));

    [Theory]
    [InlineData("\"3600\"", 3600)]
    [InlineData("\"0\"", 0)]
    public void Read_AQuotedNumber_IsSeconds(string json, int expected)
        => Assert.Equal(TimeSpan.FromSeconds(expected), JsonSerializer.Deserialize<TimeSpan>(json, Options));

    /// <summary>
    /// A string that is not a number is refused rather than silently read as zero, which would turn a
    /// malformed lifetime into an immediately expired one and produce a failure far from its cause.
    /// </summary>
    [Theory]
    [InlineData("\"an hour\"")]
    [InlineData("\"\"")]
    [InlineData("true")]
    [InlineData("null")]
    [InlineData("[3600]")]
    public void Read_AValueThatIsNotACountOfSeconds_IsRefused(string json)
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<TimeSpan>(json, Options));

    [Fact]
    public void Write_ADuration_EmitsWholeSeconds()
        => Assert.Equal("3600", JsonSerializer.Serialize(TimeSpan.FromHours(1), Options));

    /// <summary>
    /// The wire format has no room for a fraction, so a sub-second remainder is dropped rather than rounded
    /// up. Asserting the direction matters: rounding up would advertise a lifetime the token does not have.
    /// </summary>
    [Fact]
    public void Write_ASubSecondRemainder_IsTruncated()
        => Assert.Equal("59", JsonSerializer.Serialize(TimeSpan.FromSeconds(59.9), Options));

    [Fact]
    public void RoundTrip_PreservesWholeSeconds()
    {
        var json = JsonSerializer.Serialize(TimeSpan.FromSeconds(1234), Options);

        Assert.Equal(TimeSpan.FromSeconds(1234), JsonSerializer.Deserialize<TimeSpan>(json, Options));
    }
}
