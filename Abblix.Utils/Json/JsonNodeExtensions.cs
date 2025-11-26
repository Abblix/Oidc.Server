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

using System.Text.Json;
using System.Text.Json.Nodes;
using Google.Protobuf.WellKnownTypes;

namespace Abblix.Utils.Json;

/// <summary>
/// Bidirectional conversion between System.Text.Json types (JsonObject, JsonNode) and Protocol Buffers well-known types (Struct, Value).
/// Performs direct object-to-object mapping without intermediate JSON string serialization, providing efficient
/// conversion for storing JSON data in protobuf messages.
/// </summary>
public static class JsonNodeExtensions
{
    /// <summary>
    /// Converts JsonObject to protobuf Struct.
    /// </summary>
    /// <param name="jsonObject">The JsonObject to convert (null allowed).</param>
    /// <returns>Protobuf Struct representation, or null if input is null.</returns>
    public static Struct? ToStruct(this JsonObject? jsonObject)
    {
        if (jsonObject == null)
            return null;

        var protoStruct = new Struct();

        foreach (var (key, value) in jsonObject)
            protoStruct.Fields[key] = value.ToValue();

        return protoStruct;
    }

    /// <summary>
    /// Converts Dictionary&lt;string, object&gt; to protobuf Struct.
    /// </summary>
    /// <param name="dictionary">The dictionary to convert.</param>
    /// <returns>Protobuf Struct representation, or empty Struct if input is null.</returns>
    public static Struct ToStruct(this IDictionary<string, object>? dictionary)
    {
        var protoStruct = new Struct();
        if (dictionary == null)
            return protoStruct;

        foreach (var kvp in dictionary)
            protoStruct.Fields[kvp.Key] = ToValue(kvp.Value);

        return protoStruct;
    }

    /// <summary>
    /// Converts protobuf Struct to JsonObject.
    /// </summary>
    /// <param name="protoStruct">The protobuf Struct to convert (null allowed).</param>
    /// <returns>JsonObject representation, or null if input is null.</returns>
    public static JsonObject? ToJsonObject(this Struct? protoStruct)
    {
        if (protoStruct == null)
            return null;

        var jsonObject = new JsonObject();

        foreach (var field in protoStruct.Fields)
        {
            var value = field.Value.ToJsonNode();
            jsonObject[field.Key] = value;
        }

        return jsonObject;
    }

    /// <summary>
    /// Converts JsonNode to protobuf Value.
    /// Handles all JSON value types: null, boolean, number, string, array, and nested objects.
    /// </summary>
    /// <param name="node">The JsonNode to convert (null allowed).</param>
    /// <returns>Protobuf Value representation.</returns>
    private static Value ToValue(this JsonNode? node)
    {
        return node switch
        {
            null => Value.ForNull(),
            JsonValue jsonValue => jsonValue.ToValue(),
            JsonObject jsonObject => Value.ForStruct(jsonObject.ToStruct()),
            JsonArray jsonArray => Value.ForList(jsonArray.Select(ToValue).ToArray()),
            _ => Value.ForNull(),
        };
    }

    /// <summary>
    /// Converts JsonValue to protobuf Value.
    /// Handles primitive types: boolean, integer (int/long/uint/ulong), floating-point (double/float/decimal), and string.
    /// </summary>
    private static Value ToValue(this JsonValue jsonValue)
    {
        if (jsonValue.TryGetValue<bool>(out var boolValue))
            return Value.ForBool(boolValue);

        // Try all integer types
        if (jsonValue.TryGetValue<int>(out var intValue))
            return Value.ForNumber(intValue);

        if (jsonValue.TryGetValue<long>(out var longValue))
            return Value.ForNumber(longValue);

        if (jsonValue.TryGetValue<uint>(out var uintValue))
            return Value.ForNumber(uintValue);

        if (jsonValue.TryGetValue<ulong>(out var ulongValue))
            return Value.ForNumber(ulongValue);

        // Then try floating point types
        if (jsonValue.TryGetValue<double>(out var doubleValue))
            return Value.ForNumber(doubleValue);

        if (jsonValue.TryGetValue<float>(out var floatValue))
            return Value.ForNumber(floatValue);

        if (jsonValue.TryGetValue<decimal>(out var decimalValue))
            return Value.ForNumber((double)decimalValue);

        // Finally try string
        if (jsonValue.TryGetValue<string>(out var stringValue))
            return Value.ForString(stringValue);

        return Value.ForString(jsonValue.ToString());
    }

    /// <summary>
    /// Converts protobuf Value to JsonNode.
    /// Handles all protobuf value types: null, boolean, number, string, nested struct, and arrays.
    /// </summary>
    /// <param name="value">The protobuf Value to convert.</param>
    /// <returns>JsonNode representation (null for NullValue).</returns>
    private static JsonNode? ToJsonNode(this Value value)
    {
        return value.KindCase switch
        {
            Value.KindOneofCase.NullValue => null,
            Value.KindOneofCase.BoolValue => JsonValue.Create(value.BoolValue),
            Value.KindOneofCase.NumberValue => ToJsonNumber(value.NumberValue),
            Value.KindOneofCase.StringValue => JsonValue.Create(value.StringValue),
            Value.KindOneofCase.StructValue => value.StructValue.ToJsonObject(),
            Value.KindOneofCase.ListValue => new JsonArray(value.ListValue.Values.Select(ToJsonNode).ToArray()),
            _ => null
        };
    }

    /// <summary>
    /// Converts protobuf NumberValue (double) to JsonValue with type preservation.
    /// Whole numbers are stored as int or long to maintain type fidelity during round-trip conversion.
    /// </summary>
    private static JsonValue ToJsonNumber(double value)
    {
        const double tolerance = 0.001;

        // Check if the value is a whole number within int range
        if (value is >= int.MinValue and <= int.MaxValue && Math.Abs(value - Math.Round(value)) < tolerance)
            return JsonValue.Create((int)value);

        // Check if the value is a whole number within long range
        if (value is >= long.MinValue and <= long.MaxValue && Math.Abs(value - Math.Round(value)) < tolerance)
            return JsonValue.Create((long)value);

        // Otherwise, keep it as a double
        return JsonValue.Create(value);
    }

    /// <summary>
    /// Converts a C# object to protobuf Value without serialization.
    /// Handles common types (primitives, arrays, JsonNode) directly, falls back to JsonNode for complex types.
    /// </summary>
    /// <param name="obj">The object to convert (null allowed).</param>
    /// <returns>Protobuf Value representation, or null if input is null.</returns>
    public static Value? ToValue(this object? obj)
    {
        return obj switch
        {
            null => null,
            bool b => Value.ForBool(b),
            int i => Value.ForNumber(i),
            long l => Value.ForNumber(l),
            uint ui => Value.ForNumber(ui),
            ulong ul => Value.ForNumber(ul),
            double d => Value.ForNumber(d),
            float f => Value.ForNumber(f),
            decimal m => Value.ForNumber((double)m),
            string s => Value.ForString(s),
            JsonNode node => node.ToValue(),
            object[] array => Value.ForList(array.Select(ToValue).Where(v => v != null).ToArray()),
            _ => JsonSerializer.SerializeToNode(obj).ToValue()  // Fallback for complex types only
        };
    }

    /// <summary>
    /// Converts protobuf Value to C# object without serialization.
    /// Returns primitive types (bool, int/long, double, string) or JsonObject/array for complex values.
    /// </summary>
    /// <param name="value">The protobuf Value to convert (null allowed).</param>
    /// <returns>Deserialized object, or null if input is null.</returns>
    public static object? ToObject(this Value? value)
    {
        if (value == null)
            return null;

        return value.KindCase switch
        {
            Value.KindOneofCase.NullValue => null,
            Value.KindOneofCase.BoolValue => value.BoolValue,
            Value.KindOneofCase.StringValue => value.StringValue,
            Value.KindOneofCase.NumberValue => ToNumberType(value.NumberValue),
            Value.KindOneofCase.StructValue => value.StructValue.ToJsonObject(),
            Value.KindOneofCase.ListValue => value.ListValue.Values.Select(ToObject).ToArray(),
            _ => null
        };
    }

    /// <summary>
    /// Converts protobuf NumberValue (double) to the most appropriate C# numeric type.
    /// Preserves integer types (int, long) for whole numbers, returns double for fractional values.
    /// </summary>
    private static object ToNumberType(double value)
    {
        const double tolerance = 0.001;

        // Check if whole number within int range
        if (value is >= int.MinValue and <= int.MaxValue && Math.Abs(value - Math.Round(value)) < tolerance)
            return (int)Math.Round(value);

        // Check if whole number within long range
        if (value is >= long.MinValue and <= long.MaxValue && Math.Abs(value - Math.Round(value)) < tolerance)
            return (long)Math.Round(value);

        // Return as double for fractional values
        return value;
    }

    /// <summary>
    /// Converts a C# object array to protobuf ListValue.
    /// Handles any array of JSON-serializable objects.
    /// </summary>
    /// <param name="array">The array to convert (null allowed).</param>
    /// <returns>Protobuf ListValue representation, or null if input is null.</returns>
    public static ListValue? ToListValue(this object[]? array)
    {
        if (array == null)
            return null;

        var listValue = new ListValue();
        foreach (var item in array)
        {
            var value = item.ToValue();
            if (value != null)
                listValue.Values.Add(value);
        }
        return listValue;
    }

    /// <summary>
    /// Converts protobuf ListValue to C# object array without serialization.
    /// Each element is converted directly to its appropriate C# type.
    /// </summary>
    /// <param name="listValue">The protobuf ListValue to convert (null allowed).</param>
    /// <returns>Object array with elements as appropriate C# types, or null if input is null.</returns>
    public static object[]? ToObjectArray(this ListValue? listValue)
    {
        if (listValue == null)
            return null;

        return listValue.Values
            .Select(v => v.ToObject())
            .ToArray()!;
    }

    /// <summary>
    /// Converts protobuf Struct to Dictionary&lt;string, object&gt;.
    /// </summary>
    /// <param name="protoStruct">The protobuf Struct to convert.</param>
    /// <returns>Dictionary representation of the Struct, or empty dictionary if input is null.</returns>
    public static Dictionary<string, object> ToDictionary(this Struct? protoStruct)
    {
        if (protoStruct == null)
            return new Dictionary<string, object>();

        var result = new Dictionary<string, object>();
        foreach (var field in protoStruct.Fields)
        {
            var value = ToObject(field.Value);
            if (value != null)
                result[field.Key] = value;
        }

        return result;
    }
}
