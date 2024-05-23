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

using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests;

using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

/// <summary>
/// Unit tests for the ArrayConverter&lt;TElement, TConverter&gt; class.
/// These tests cover the serialization and deserialization of arrays using a custom JSON converter for individual elements.
/// </summary>
public class ArrayConverterTests
{
    /// <summary>
    /// A custom JSON converter for string elements used for testing the ArrayConverter.
    /// </summary>
    private class CustomElementConverter : JsonConverter<string>
    {
        public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => reader.GetString();

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
            => writer.WriteStringValue(value);
    }

    /// <summary>
    /// Tests the deserialization of a null JSON token.
    /// Ensures that the converter returns null when the JSON token is null.
    /// </summary>
    [Fact]
    public void Read_NullToken_ReturnsNull()
    {
        const string json = "null";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        var converter = new ArrayConverter<string, CustomElementConverter>();

        var result = converter.Read(ref reader, typeof(string[]), new JsonSerializerOptions());

        Assert.Null(result);
    }

    /// <summary>
    /// Tests the deserialization of an empty JSON array.
    /// Ensures that the converter returns an empty array when the JSON array is empty.
    /// </summary>
    [Fact]
    public void Read_EmptyArray_ReturnsEmptyArray()
    {
        const string json = "[]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        var converter = new ArrayConverter<string, CustomElementConverter>();

        var result = converter.Read(ref reader, typeof(string[]), new JsonSerializerOptions());
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    /// <summary>
    /// Tests the deserialization of a JSON array with string elements.
    /// Ensures that the converter returns an array with the correct elements.
    /// </summary>
    [Fact]
    public void Read_ArrayWithElements_ReturnsArray()
    {
        const string json = "[\"one\", \"two\", \"three\"]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        var converter = new ArrayConverter<string, CustomElementConverter>();

        var result = converter.Read(ref reader, typeof(string[]), new JsonSerializerOptions());

        Assert.Equal(new[] { "one", "two", "three" }, result);
    }

    /// <summary>
    /// Tests the serialization of a null array.
    /// Ensures that the converter writes null to the JSON output when the array is null.
    /// </summary>
    [Fact]
    public void Write_NullValue_WritesNull()
    {
        var converter = new ArrayConverter<string, CustomElementConverter>();
        var options = new JsonSerializerOptions();
        var memoryStream = new MemoryStream();

        using (var writer = new Utf8JsonWriter(memoryStream))
            converter.Write(writer, null, options);

        var json = System.Text.Encoding.UTF8.GetString(memoryStream.ToArray());

        Assert.Equal("null", json);
    }

    /// <summary>
    /// Tests the serialization of an empty array.
    /// Ensures that the converter writes an empty JSON array when the array is empty.
    /// </summary>
    [Fact]
    public void Write_EmptyArray_WritesEmptyArray()
    {
        var converter = new ArrayConverter<string, CustomElementConverter>();
        var options = new JsonSerializerOptions();
        var memoryStream = new MemoryStream();

        using (var writer = new Utf8JsonWriter(memoryStream))
            converter.Write(writer, [], options);

        var json = System.Text.Encoding.UTF8.GetString(memoryStream.ToArray());

        Assert.Equal("[]", json);
    }

    /// <summary>
    /// Tests the serialization of an array with string elements.
    /// Ensures that the converter writes the correct JSON array when the array contains elements.
    /// </summary>
    [Fact]
    public void Write_ArrayWithElements_WritesArray()
    {
        var converter = new ArrayConverter<string, CustomElementConverter>();
        var options = new JsonSerializerOptions();
        var memoryStream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(memoryStream))
            converter.Write(writer, ["one", "two", "three"], options);

        var json = System.Text.Encoding.UTF8.GetString(memoryStream.ToArray());

        Assert.Equal("[\"one\",\"two\",\"three\"]", json);
    }
}
