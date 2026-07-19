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

using System.Text.Json.Nodes;
using Abblix.Utils.Json;
using Google.Protobuf.WellKnownTypes;

namespace Abblix.Utils.UnitTests.Json;

/// <summary>
/// Tests for JsonNodeExtensions protobuf conversion methods.
/// </summary>
public class JsonNodeExtensionsTests
{
    #region ObjectToProtoValue / ProtoValueToObject Tests

    [Fact]
    public void ObjectToProtoValue_Null_ReturnsNull()
    {
        // Act
        var result = ((object?)null).ToValue();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ProtoValueToObject_Null_ReturnsNull()
    {
        // Act
        var result = ((Value?)null).ToObject();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ObjectToProtoValue_Bool_RoundTrip()
    {
        // Arrange
        var value = true;

        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.BoolValue, proto.KindCase);
        Assert.IsType<bool>(result);
        Assert.Equal(value, result);
    }

    [Fact]
    public void ObjectToProtoValue_String_RoundTrip()
    {
        // Arrange
        var value = "test@example.com";

        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.StringValue, proto.KindCase);
        Assert.IsType<string>(result);
        Assert.Equal(value, result);
    }

    [Theory]
    [InlineData(42)]
    [InlineData(0)]
    [InlineData(-100)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void ObjectToProtoValue_Int_PreservesType(int value)
    {
        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.NumberValue, proto.KindCase);
        Assert.IsType<int>(result);
        Assert.Equal(value, result);
    }

    [Theory]
    [InlineData(42L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void ObjectToProtoValue_Long_PreservesType(long value)
    {
        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.NumberValue, proto.KindCase);

        // Note: values within int range will be converted to int
        if (value is >= int.MinValue and <= int.MaxValue)
        {
            Assert.IsType<int>(result);
            Assert.Equal((int)value, result);
        }
        else
        {
            Assert.IsType<long>(result);
            Assert.Equal(value, result);
        }
    }

    [Theory]
    [InlineData(3.14)]
    [InlineData(-2.5)]
    [InlineData(0.001)]
    public void ObjectToProtoValue_Double_RoundTrip(double value)
    {
        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.NumberValue, proto.KindCase);
        Assert.IsType<double>(result);
        Assert.Equal(value, (double)result, 0.0001);
    }

    [Fact]
    public void ObjectToProtoValue_Float_ConvertsToDouble()
    {
        // Arrange
        var value = 3.14f;

        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.NumberValue, proto.KindCase);
        Assert.IsType<double>(result);
        Assert.Equal(value, (double)result, 0.0001);
    }

    [Fact]
    public void ObjectToProtoValue_Decimal_ConvertsToDouble()
    {
        // Arrange
        var value = 123.456m;

        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.NumberValue, proto.KindCase);
        Assert.IsType<double>(result);
        Assert.Equal((double)value, (double)result, 0.0001);
    }

    [Fact]
    public void ObjectToProtoValue_JsonObject_RoundTrip()
    {
        // Arrange
        var value = new JsonObject
        {
            ["name"] = "John",
            ["age"] = 42,
            ["active"] = true
        };

        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.StructValue, proto.KindCase);
        Assert.IsType<JsonObject>(result);

        var jsonResult = (JsonObject)result;
        Assert.Equal("John", jsonResult["name"]!.GetValue<string>());
        Assert.Equal(42, jsonResult["age"]!.GetValue<int>());
        Assert.True(jsonResult["active"]!.GetValue<bool>());
    }

    [Fact]
    public void ObjectToProtoValue_Array_RoundTrip()
    {
        // Arrange
        object[] value = ["apple", "banana", "cherry"];

        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(Value.KindOneofCase.ListValue, proto.KindCase);
        Assert.IsType<object[]>(result);

        var arrayResult = (object[])result;
        Assert.Equal(3, arrayResult.Length);
        Assert.Equal("apple", arrayResult[0]);
        Assert.Equal("banana", arrayResult[1]);
        Assert.Equal("cherry", arrayResult[2]);
    }

    [Fact]
    public void ObjectToProtoValue_MixedArray_PreservesTypes()
    {
        // Arrange
        object[] value = ["text", 42, true, 3.14];

        // Act
        var proto = value.ToValue();
        var result = proto.ToObject();

        // Assert
        Assert.NotNull(proto);
        var arrayResult = (object[])result!;
        Assert.Equal(4, arrayResult.Length);
        Assert.IsType<string>(arrayResult[0]);
        Assert.Equal("text", arrayResult[0]);
        Assert.IsType<int>(arrayResult[1]);
        Assert.Equal(42, arrayResult[1]);
        Assert.True(Assert.IsType<bool>(arrayResult[2]));
        Assert.IsType<double>(arrayResult[3]);
        Assert.Equal(3.14, (double)arrayResult[3], 0.0001);
    }

    #endregion

    #region ToProtoStruct / ToJsonObject Tests

    [Fact]
    public void ToProtoStruct_Null_ReturnsNull()
    {
        // Act
        var result = ((JsonObject?)null).ToStruct();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ToJsonObject_Null_ReturnsNull()
    {
        // Act
        var result = ((Struct?)null).ToJsonObject();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ToProtoStruct_EmptyObject_RoundTrip()
    {
        // Arrange
        var jsonObject = new JsonObject();

        // Act
        var proto = jsonObject.ToStruct();
        var result = proto.ToJsonObject();

        // Assert
        Assert.NotNull(proto);
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ToProtoStruct_NestedObject_RoundTrip()
    {
        // Arrange
        var jsonObject = new JsonObject
        {
            ["user"] = new JsonObject
            {
                ["name"] = "John Doe",
                ["email"] = "john@example.com",
                ["settings"] = new JsonObject
                {
                    ["theme"] = "dark",
                    ["notifications"] = true
                }
            },
            ["roles"] = new JsonArray("admin", "user")
        };

        // Act
        var proto = jsonObject.ToStruct();
        var result = proto.ToJsonObject();

        // Assert
        Assert.NotNull(proto);
        Assert.NotNull(result);

        var user = result["user"]!.AsObject();
        Assert.Equal("John Doe", user["name"]!.GetValue<string>());
        Assert.Equal("john@example.com", user["email"]!.GetValue<string>());

        var settings = user["settings"]!.AsObject();
        Assert.Equal("dark", settings["theme"]!.GetValue<string>());
        Assert.True(settings["notifications"]!.GetValue<bool>());

        var roles = result["roles"]!.AsArray();
        Assert.Equal(2, roles.Count);
        Assert.Equal("admin", roles[0]!.GetValue<string>());
        Assert.Equal("user", roles[1]!.GetValue<string>());
    }

    #endregion

    #region ObjectArrayToProtoListValue / ProtoListValueToObjectArray Tests

    [Fact]
    public void ObjectArrayToProtoListValue_Null_ReturnsNull()
    {
        // Act
        var result = ((object[]?)null).ToListValue();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ProtoListValueToObjectArray_Null_ReturnsNull()
    {
        // Act
        var result = ((ListValue?)null).ToObjectArray();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ObjectArrayToProtoListValue_Empty_RoundTrip()
    {
        // Arrange
        var array = Array.Empty<object>();

        // Act
        var proto = array.ToListValue();
        var result = proto.ToObjectArray();

        // Assert
        Assert.NotNull(proto);
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ObjectArrayToProtoListValue_StringArray_RoundTrip()
    {
        // Arrange
        object[] array = ["en-US", "en-GB", "en"];

        // Act
        var proto = array.ToListValue();
        var result = proto.ToObjectArray();

        // Assert
        Assert.NotNull(proto);
        Assert.NotNull(result);
        Assert.Equal(3, result.Length);
        Assert.Equal("en-US", result[0]);
        Assert.Equal("en-GB", result[1]);
        Assert.Equal("en", result[2]);
    }

    [Fact]
    public void ObjectArrayToProtoListValue_NumberArray_PreservesIntType()
    {
        // Arrange
        object[] array = [1, 2, 3, 42, 100];

        // Act
        var proto = array.ToListValue();
        var result = proto.ToObjectArray();

        // Assert
        Assert.NotNull(proto);
        Assert.NotNull(result);
        Assert.Equal(5, result.Length);

        foreach (var item in result)
        {
            Assert.IsType<int>(item);
        }

        Assert.Equal(1, result[0]);
        Assert.Equal(42, result[3]);
    }

    [Fact]
    public void ObjectArrayToProtoListValue_ComplexArray_RoundTrip()
    {
        // Arrange
        object[] array =
        [
            "text",
            42,
            true,
            new JsonObject { ["nested"] = "value" }
        ];

        // Act
        var proto = array.ToListValue();
        var result = proto.ToObjectArray();

        // Assert
        Assert.NotNull(proto);
        Assert.NotNull(result);
        Assert.Equal(4, result.Length);
        Assert.IsType<string>(result[0]);
        Assert.IsType<int>(result[1]);
        Assert.IsType<bool>(result[2]);
        Assert.IsType<JsonObject>(result[3]);

        var nested = (JsonObject)result[3];
        Assert.Equal("value", nested["nested"]!.GetValue<string>());
    }

    #endregion

    #region Type Preservation Edge Cases

    [Theory]
    [InlineData(0.0)]      // Should become int 0
    [InlineData(1.0)]      // Should become int 1
    [InlineData(42.0)]     // Should become int 42
    [InlineData(-5.0)]     // Should become int -5
    public void NumberTypePreservation_WholeNumberDouble_BecomesInt(double value)
    {
        // Act
        var proto = Value.ForNumber(value);
        var result = proto.ToObject();

        // Assert
        Assert.IsType<int>(result);
        Assert.Equal((int)value, result);
    }

    [Theory]
    [InlineData(1.5)]
    [InlineData(3.14159)]
    [InlineData(-2.7)]
    public void NumberTypePreservation_FractionalDouble_StaysDouble(double value)
    {
        // Act
        var proto = Value.ForNumber(value);
        var result = proto.ToObject();

        // Assert
        Assert.IsType<double>(result);
        Assert.Equal(value, (double)result, 0.0001);
    }

    [Fact]
    public void NumberTypePreservation_LargeWholeNumber_BecomesLong()
    {
        // Arrange - number larger than int.MaxValue but whole
        var value = int.MaxValue + 1000.0;

        // Act
        var proto = Value.ForNumber(value);
        var result = proto.ToObject();

        // Assert
        Assert.IsType<long>(result);
        Assert.Equal((long)value, result);
    }

    #endregion
}
