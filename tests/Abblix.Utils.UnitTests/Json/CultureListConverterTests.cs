// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Globalization;
using System.Text.Json;
using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests.Json;

/// <summary>
/// The converter behind <c>ui_locales</c> and <c>claims_locales</c>. OpenID Connect Core 1.0 section 3.1.2.1 gives
/// both as a space-separated list of BCP 47 language tags, and a request object carries its parameters as claims of
/// that same shape (section 6.1), so a string is read as the list; an array, which clients already send, is read too.
/// </summary>
public class CultureListConverterTests
{
    private static readonly JsonSerializerOptions Options = new() { Converters = { new CultureListConverter() } };

    [Theory]
    [InlineData("\"en\"", new[] { "en" })]
    [InlineData("\"en fr-CA\"", new[] { "en", "fr-CA" })]
    [InlineData("\" en  fr-CA \"", new[] { "en", "fr-CA" })]
    [InlineData("[\"en\",\"fr-CA\"]", new[] { "en", "fr-CA" })]
    [InlineData("\"   \"", new string[0])]
    public void AListOfLanguageTags_ProducesThoseCultures(string json, string[] names)
    {
        var cultures = JsonSerializer.Deserialize<CultureInfo[]>(json, Options);

        Assert.Equal(names, cultures!.Select(culture => culture.Name));
    }

    [Fact]
    public void Null_ProducesNoList()
        => Assert.Null(JsonSerializer.Deserialize<CultureInfo[]>("null", Options));

    [Theory]
    [InlineData("\"en !\"")]
    [InlineData("[\"!\"]")]
    [InlineData("[null,\"en\"]")]
    [InlineData("[\"\",\"en\"]")]
    [InlineData("\"en und\"")]
    [InlineData("\"x-iv\"")]
    [InlineData("[\"und\"]")]
    [InlineData("\"en\\t\"")]
    [InlineData("\"\\t\"")]
    [InlineData("[5]")]
    [InlineData("5")]
    [InlineData("{}")]
    public void AListWithAnEntryNoCultureCanCarry_IsRefused(string json)
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<CultureInfo[]>(json, Options));
}
