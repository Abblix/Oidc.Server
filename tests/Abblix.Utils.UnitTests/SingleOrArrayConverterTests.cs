// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests;

public class SingleOrArrayConverterTests
{
    private readonly SingleOrArrayConverter<string> _converter = new();

    /// <summary>
    /// A DTO whose single-or-array value is a property inside an object, with another property
    /// after it. This is the real-world shape (e.g. a "resource" array in a JWT request object) that
    /// exposed the over-read bug: the top-level-array tests below cannot, because at end of stream
    /// the stray read past EndArray simply returns false.
    /// </summary>
    private sealed class Dto
    {
        [JsonPropertyName("values")]
        [JsonConverter(typeof(SingleOrArrayConverter<string>))]
        public string[]? Values { get; set; }

        [JsonPropertyName("other")]
        public string? Other { get; set; }
    }

    [Theory]
    // Array value followed by another property — the read past EndArray would land on the next
    // property name and throw before the fix.
    [InlineData("{\"values\":[\"a\",\"b\"],\"other\":\"x\"}", new[] { "a", "b" }, "x")]
    // Array value as the last property — the read past EndArray would land on the object's EndObject.
    [InlineData("{\"other\":\"x\",\"values\":[\"a\",\"b\"]}", new[] { "a", "b" }, "x")]
    // Single scalar form inside an object still works.
    [InlineData("{\"values\":\"a\",\"other\":\"x\"}", new[] { "a" }, "x")]
    // Single-element array inside an object.
    [InlineData("{\"values\":[\"a\"],\"other\":\"x\"}", new[] { "a" }, "x")]
    public void Read_ArrayInsideObject_DeserializesWithoutOverReading(
        string json, string[] expectedValues, string expectedOther)
    {
        var dto = JsonSerializer.Deserialize<Dto>(json);

        Assert.NotNull(dto);
        Assert.Equal(expectedValues, dto.Values);
        Assert.Equal(expectedOther, dto.Other);
    }

    [Theory]
    [InlineData("\"singleString\"", new[] { "singleString" })]
    [InlineData("[\"string1\", \"string2\"]", new[] { "string1", "string2" })]
    [InlineData("null", null)]
    public void Read_ValidJson_ReturnsExpectedArray(string json, string[]? expected)
    {
        var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(json)));
        reader.Read(); // Move to the first token

        var result = _converter.Read(ref reader, typeof(string[]), new JsonSerializerOptions());

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("123")]
    [InlineData("{\"key\":\"value\"}")]
    public void Read_InvalidJson_ThrowsJsonException(string json)
    {
        Assert.Throws<JsonException>(() =>
        {
            var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(json)));
            reader.Read(); // Move to the first token
            return _converter.Read(ref reader, typeof(string[]), new JsonSerializerOptions());
        });
    }

    [Theory]
    [InlineData(new[] { "singleString" }, "\"singleString\"")]
    [InlineData(new[] { "string1", "string2" }, "[\"string1\",\"string2\"]")]
    [InlineData(null, "null")]
    public void Write_ValidArray_WritesExpectedJson(string[]? value, string expectedJson)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
            _converter.Write(writer, value, new JsonSerializerOptions());

        var json = Encoding.UTF8.GetString(stream.ToArray());
        Assert.Equal(expectedJson, json);
    }
}
