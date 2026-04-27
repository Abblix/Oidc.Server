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
    private sealed class CustomElementConverter : JsonConverter<string>
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
        reader.Read();
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
        reader.Read();
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
        reader.Read();
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

    private sealed class IntElementConverter : JsonConverter<int>
    {
        public override int Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => reader.GetInt32();

        public override void Write(Utf8JsonWriter writer, int value, JsonSerializerOptions options)
            => writer.WriteNumberValue(value);
    }

    private sealed class BoolElementConverter : JsonConverter<bool>
    {
        public override bool Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => reader.GetBoolean();

        public override void Write(Utf8JsonWriter writer, bool value, JsonSerializerOptions options)
            => writer.WriteBooleanValue(value);
    }

    private sealed record Point(int X, int Y);

    private sealed class PointElementConverter : JsonConverter<Point>
    {
        public override Point Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject) throw new JsonException();
            int x = 0, y = 0;
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject) return new Point(x, y);
                if (reader.TokenType != JsonTokenType.PropertyName) throw new JsonException();
                var name = reader.GetString();
                reader.Read();
                if (name == "x") x = reader.GetInt32();
                else if (name == "y") y = reader.GetInt32();
                else throw new JsonException();
            }
            throw new JsonException();
        }

        public override void Write(Utf8JsonWriter writer, Point value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteNumber("x", value.X);
            writer.WriteNumber("y", value.Y);
            writer.WriteEndObject();
        }
    }

    private sealed class IntArrayElementConverter : JsonConverter<int[]>
    {
        public override int[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartArray) throw new JsonException();
            var items = new List<int>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray) return items.ToArray();
                items.Add(reader.GetInt32());
            }
            throw new JsonException();
        }

        public override void Write(Utf8JsonWriter writer, int[] value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();
            foreach (var n in value) writer.WriteNumberValue(n);
            writer.WriteEndArray();
        }
    }

    /// <summary>
    /// Verifies that Read accepts JSON Number tokens by delegating to the inner converter.
    /// Regression coverage for the previous string-only invariant.
    /// </summary>
    [Fact]
    public void Read_ArrayOfNumbers_ReturnsIntArray()
    {
        const string json = "[1, 2, 3]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        var converter = new ArrayConverter<int, IntElementConverter>();

        var result = converter.Read(ref reader, typeof(int[]), new JsonSerializerOptions());

        Assert.Equal(new[] { 1, 2, 3 }, result);
    }

    /// <summary>
    /// Verifies that Read accepts JSON True / False tokens by delegating to the inner converter.
    /// </summary>
    [Fact]
    public void Read_ArrayOfBooleans_ReturnsBoolArray()
    {
        const string json = "[true, false, true]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        var converter = new ArrayConverter<bool, BoolElementConverter>();

        var result = converter.Read(ref reader, typeof(bool[]), new JsonSerializerOptions());

        Assert.Equal(new[] { true, false, true }, result);
    }

    /// <summary>
    /// Verifies that Read accepts JSON object tokens, advancing the reader past the matching EndObject.
    /// </summary>
    [Fact]
    public void Read_ArrayOfObjects_ReturnsObjectArray()
    {
        const string json = "[{\"x\":1,\"y\":2},{\"x\":3,\"y\":4}]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        var converter = new ArrayConverter<Point, PointElementConverter>();

        var result = converter.Read(ref reader, typeof(Point[]), new JsonSerializerOptions());

        Assert.Equal(new[] { new Point(1, 2), new Point(3, 4) }, result);
    }

    /// <summary>
    /// Verifies that Read accepts JSON array tokens (nested arrays), advancing the reader past the matching EndArray.
    /// </summary>
    [Fact]
    public void Read_ArrayOfArrays_ReturnsNestedArrays()
    {
        const string json = "[[1,2],[3,4,5]]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        var converter = new ArrayConverter<int[], IntArrayElementConverter>();

        var result = converter.Read(ref reader, typeof(int[][]), new JsonSerializerOptions());

        Assert.NotNull(result);
        Assert.Equal(2, result.Length);
        Assert.Equal(new[] { 1, 2 }, result[0]);
        Assert.Equal(new[] { 3, 4, 5 }, result[1]);
    }

    /// <summary>
    /// JSON null inside the array yields default(TElement) for an unconstrained value-type element,
    /// without invoking the inner converter. For int that is 0, since C# does not lift unconstrained
    /// generic T to Nullable T even with a T? annotation.
    /// </summary>
    [Fact]
    public void Read_ArrayWithNullElement_ReturnsDefaultForValueType()
    {
        const string json = "[1, null, 2]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        var converter = new ArrayConverter<int, IntElementConverter>();

        var result = converter.Read(ref reader, typeof(int[]), new JsonSerializerOptions());

        Assert.NotNull(result);
        Assert.Equal(new[] { 1, 0, 2 }, result);
    }

    /// <summary>
    /// JSON null inside the array yields null for a reference-type element, without invoking the inner converter.
    /// </summary>
    [Fact]
    public void Read_ArrayWithNullElement_ReturnsNullForReferenceType()
    {
        const string json = "[\"a\", null, \"b\"]";
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        reader.Read();
        var converter = new ArrayConverter<string, CustomElementConverter>();

        var result = converter.Read(ref reader, typeof(string[]), new JsonSerializerOptions());

        Assert.NotNull(result);
        Assert.Equal(3, result.Length);
        Assert.Equal("a", result[0]);
        Assert.Null(result[1]);
        Assert.Equal("b", result[2]);
    }

    /// <summary>
    /// Verifies Write/Read round-trip for an int array using the IntElementConverter.
    /// Locks in the symmetry contract so a future regression on either side fails the test.
    /// </summary>
    [Fact]
    public void RoundTrip_IntArray_ProducesEqualArray()
    {
        var converter = new ArrayConverter<int, IntElementConverter>();
        var options = new JsonSerializerOptions();
        int[] original = [10, 20, 30];

        using var memoryStream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(memoryStream))
            converter.Write(writer, original, options);

        var json = System.Text.Encoding.UTF8.GetString(memoryStream.ToArray());
        Assert.Equal("[10,20,30]", json);

        var reader = new Utf8JsonReader(memoryStream.ToArray());
        reader.Read();
        var roundTripped = converter.Read(ref reader, typeof(int[]), options);

        Assert.Equal(original, roundTripped);
    }

    /// <summary>
    /// Verifies Write/Read round-trip for an array of complex objects.
    /// </summary>
    [Fact]
    public void RoundTrip_ObjectArray_ProducesEqualArray()
    {
        var converter = new ArrayConverter<Point, PointElementConverter>();
        var options = new JsonSerializerOptions();
        Point[] original = [new Point(1, 2), new Point(3, 4)];

        using var memoryStream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(memoryStream))
            converter.Write(writer, original, options);

        var reader = new Utf8JsonReader(memoryStream.ToArray());
        reader.Read();
        var roundTripped = converter.Read(ref reader, typeof(Point[]), options);

        Assert.Equal(original, roundTripped);
    }
}
