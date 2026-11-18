// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests.Json;

/// <summary>
/// Pins that a space-separated list read from JSON holds its values only: a doubled, leading or trailing space
/// separates no value, as the form readers of the server's adapters take it.
/// </summary>
public class SpaceSeparatedValuesConverterTests
{
    private sealed record Holder([property: JsonConverter(typeof(SpaceSeparatedValuesConverter))] string[]? Values);

    [Theory]
    [InlineData("\"a b\"", new[] { "a", "b" })]
    [InlineData("\"a \"", new[] { "a" })]
    [InlineData("\" a  b \"", new[] { "a", "b" })]
    [InlineData("\"\"", new string[0])]
    public void Read_KeepsTheValuesAlone(string json, string[] expected)
        => Assert.Equal(expected, JsonSerializer.Deserialize<Holder>($"{{\"Values\":{json}}}")!.Values);

    [Fact]
    public void Read_KeepsAnAbsentListAbsent()
        => Assert.Null(JsonSerializer.Deserialize<Holder>("{\"Values\":null}")!.Values);
}
