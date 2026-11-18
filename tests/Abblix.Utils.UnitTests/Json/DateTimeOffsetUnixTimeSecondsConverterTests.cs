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
/// A Unix time is a NumericDate (RFC 7519 section 2), a number of seconds that may carry a fraction; the fraction is
/// dropped, since the instants read here are kept to the second.
/// </summary>
public class DateTimeOffsetUnixTimeSecondsConverterTests
{
    private static readonly JsonSerializerOptions Options = new() { Converters = { new DateTimeOffsetUnixTimeSecondsConverter() } };

    [Theory]
    [InlineData("1700000000", 1700000000)]
    [InlineData("1700000000.5", 1700000000)]
    [InlineData("1700000000.999", 1700000000)]
    [InlineData("-1.5", -1)]
    [InlineData("0", 0)]
    public void ANumberOfSeconds_IsTheInstantItNames_ToTheSecond(string json, long seconds)
        => Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(seconds), JsonSerializer.Deserialize<DateTimeOffset>(json, Options));
}
