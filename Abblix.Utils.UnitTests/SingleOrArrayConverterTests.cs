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
using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests;

public class SingleOrArrayConverterTests
{
    private readonly SingleOrArrayConverter<string> _converter = new();

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
