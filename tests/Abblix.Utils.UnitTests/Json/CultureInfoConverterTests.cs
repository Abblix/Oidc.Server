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
/// The converter behind <c>ui_locales</c> and <c>claims_locales</c>, which arrive as a space-separated list of
/// BCP 47 language tags (OpenID Connect Core 1.0 section 3.1.2.1) and are bound one element at a time through
/// <see cref="ArrayConverter{TElement,TConverter}"/>.
/// </summary>
/// <remarks>
/// The cases are the token shapes a real request produces: a language tag, a language-region tag, an absent
/// value, and a token of the wrong JSON type. The round trip matters as much as either direction on its own,
/// because the converter maps the invariant culture to <c>null</c> and back, and that pair has to agree with
/// itself or a value survives one leg and not the other.
/// </remarks>
public class CultureInfoConverterTests
{
    private static readonly JsonSerializerOptions Options = new() { Converters = { new CultureInfoConverter() } };

    [Theory]
    [InlineData("\"en\"", "en")]
    [InlineData("\"en-US\"", "en-US")]
    [InlineData("\"ru-RU\"", "ru-RU")]
    public void Read_ALanguageTag_ProducesThatCulture(string json, string expectedName)
    {
        var culture = JsonSerializer.Deserialize<CultureInfo>(json, Options);

        Assert.NotNull(culture);
        Assert.Equal(expectedName, culture.Name);
    }

    /// <summary>
    /// An absent element is not an error: the invariant culture is how this converter spells "no preference".
    /// </summary>
    /// <remarks>
    /// Driven through the converter directly rather than through <see cref="JsonSerializer"/>, because the
    /// serializer answers <c>null</c> for a reference type before it ever calls a converter that has not
    /// opted into handling null. Production reaches this arm the other way: <c>ui_locales</c> is bound by
    /// <see cref="ArrayConverter{TElement,TConverter}"/>, which reads each element through the element
    /// converter itself. Testing it through the serializer would have asserted the serializer's behaviour and
    /// left this arm as dark as it was.
    /// </remarks>
    [Fact]
    public void Read_ANullElement_ProducesTheInvariantCulture()
    {
        var reader = new Utf8JsonReader("null"u8);
        reader.Read();

        var culture = new CultureInfoConverter().Read(ref reader, typeof(CultureInfo), Options);

        Assert.Same(CultureInfo.InvariantCulture, culture);
    }

    /// <summary>
    /// The production path end to end: a space-separated list of language tags reaches this converter one
    /// element at a time through the array converter that binds <c>ui_locales</c>.
    /// </summary>
    [Fact]
    public void Read_ThroughTheArrayConverter_BindsEveryTag()
    {
        var options = new JsonSerializerOptions
        {
            Converters = { new ArrayConverter<CultureInfo, CultureInfoConverter>() },
        };

        var cultures = JsonSerializer.Deserialize<CultureInfo[]>("[\"en-US\",\"ru-RU\"]", options);

        Assert.NotNull(cultures);
        Assert.Equal(["en-US", "ru-RU"], cultures.Select(c => c.Name));
    }

    /// <summary>
    /// A number where a language tag belongs is a malformed request rather than an unknown culture, so it is
    /// refused at the parse rather than resolved to something.
    /// </summary>
    [Theory]
    [InlineData("42")]
    [InlineData("true")]
    [InlineData("[\"en\"]")]
    public void Read_ATokenOfTheWrongType_IsRefused(string json)
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<CultureInfo>(json, Options));

    [Fact]
    public void Write_ACulture_EmitsItsName()
        => Assert.Equal("\"en-US\"", JsonSerializer.Serialize(new CultureInfo("en-US"), Options));

    /// <summary>
    /// The mirror of the null read: the invariant culture is the absence of a preference, so it goes back on
    /// the wire as an absent value rather than as the empty name it carries in memory.
    /// </summary>
    [Fact]
    public void Write_TheInvariantCulture_EmitsNull()
        => Assert.Equal("null", JsonSerializer.Serialize(CultureInfo.InvariantCulture, Options));

    [Theory]
    [InlineData("en")]
    [InlineData("en-US")]
    public void RoundTrip_PreservesTheTag(string name)
    {
        var json = JsonSerializer.Serialize(new CultureInfo(name), Options);
        var back = JsonSerializer.Deserialize<CultureInfo>(json, Options);

        Assert.NotNull(back);
        Assert.Equal(name, back.Name);
    }
}
