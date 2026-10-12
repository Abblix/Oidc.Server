// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests.Json;

/// <summary>
/// Every converter that reads what a client sent refuses a value it cannot read with a <see cref="JsonException"/>,
/// the one exception a caller of the serializer is told to expect, so a malformed member of a request object is
/// answered as an invalid request object rather than reaching the host as a server error.
/// </summary>
public class MalformedValueTests
{
    private static void AssertRefused<T>(string json, JsonConverter converter)
    {
        var options = new JsonSerializerOptions { Converters = { converter } };

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<T>(json, options));
    }

    [Theory]
    [InlineData("\"!\"")]
    [InlineData("\"en_US!\"")]
    [InlineData("5")]
    public void ACultureNoNameCanCarry_IsRefused(string json)
        => AssertRefused<CultureInfo>(json, new CultureInfoConverter());

    [Theory]
    [InlineData("[\"!\"]")]
    [InlineData("[5]")]
    public void ALocaleListWithAnElementNoCultureCanCarry_IsRefused(string json)
        => AssertRefused<CultureInfo[]>(json, new CultureListConverter());

    [Theory]
    [InlineData("5")]
    [InlineData("true")]
    [InlineData("{}")]
    [InlineData("[\"openid\"]")]
    public void ASpaceSeparatedListThatIsNoString_IsRefused(string json)
        => AssertRefused<string[]>(json, new SpaceSeparatedValuesConverter());

    [Theory]
    [InlineData("5")]
    [InlineData("{}")]
    [InlineData("\"!!!\"")]
    public void Base64UrlTextThatIsNoBase64Url_IsRefused(string json)
        => AssertRefused<byte[]>(json, new Base64UrlTextEncoderConverter());

    [Theory]
    [InlineData("\"1700000000\"")]
    [InlineData("99999999999999999")]
    [InlineData("1e300")]
    [InlineData("-99999999999999999")]
    public void AUnixTimeNoInstantCanCarry_IsRefused(string json)
        => AssertRefused<DateTimeOffset>(json, new DateTimeOffsetUnixTimeSecondsConverter());

    [Theory]
    [InlineData("\"x\"")]
    [InlineData("1.5")]
    [InlineData("-1")]
    public void ADurationNoTimeSpanCanCarry_IsRefused(string json)
        => AssertRefused<TimeSpan>(json, new TimeSpanSecondsConverter());

    [Theory]
    [InlineData("5")]
    [InlineData("[5]")]
    [InlineData("[null]")]
    public void ASingleOrArrayOfStringsHoldingSomethingElse_IsRefused(string json)
        => AssertRefused<string[]>(json, new SingleOrArrayConverter<string>());
}
