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
using System.Text.Json.Serialization;

namespace Abblix.Jwt;

/// <summary>
/// Custom JSON converter for JsonWebKey that handles polymorphic serialization/deserialization
/// based on the "kty" (key type) discriminator while ensuring the KeyType property is serialized
/// in both polymorphic and direct serialization scenarios.
/// </summary>
public class JsonWebKeyConverter : JsonConverter<JsonWebKey>
{
    /// <summary>
    /// Creates a fresh copy of JsonSerializerOptions excluding this converter to avoid infinite recursion.
    /// </summary>
    private static JsonSerializerOptions CreateOptionsForDerivedType(JsonSerializerOptions options)
    {
        var result = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = options.DefaultIgnoreCondition,
            PropertyNamingPolicy = options.PropertyNamingPolicy,
            WriteIndented = options.WriteIndented,
            PropertyNameCaseInsensitive = options.PropertyNameCaseInsensitive,
        };

        // Copy only non-JsonWebKeyConverter instances from original options
        foreach (var converter in options.Converters)
        {
            if (converter is not JsonWebKeyConverter)
            {
                result.Converters.Add(converter);
            }
        }

        return result;
    }

    public override JsonWebKey? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected StartObject token");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        if (!root.TryGetProperty(JsonWebKeyPropertyNames.KeyType, out var ktyElement))
        {
            throw new JsonException($"Missing required '{JsonWebKeyPropertyNames.KeyType}' property");
        }

        var kty = ktyElement.GetString();
        if (string.IsNullOrEmpty(kty))
        {
            throw new JsonException($"'{JsonWebKeyPropertyNames.KeyType}' property cannot be null or empty");
        }

        var rawJson = root.GetRawText();
        var serializerOptions = CreateOptionsForDerivedType(options);

        return kty switch
        {
            JsonWebKeyTypes.Rsa => JsonSerializer.Deserialize<RsaJsonWebKey>(rawJson, serializerOptions),
            JsonWebKeyTypes.EllipticCurve => JsonSerializer.Deserialize<EllipticCurveJsonWebKey>(rawJson, serializerOptions),
            JsonWebKeyTypes.Octet => JsonSerializer.Deserialize<OctetJsonWebKey>(rawJson, serializerOptions),
            _ => throw new JsonException($"Unknown key type: {kty}"),
        };
    }

    public override void Write(Utf8JsonWriter writer, JsonWebKey value, JsonSerializerOptions options)
    {
        var serializerOptions = CreateOptionsForDerivedType(options);

        // Serialize the concrete type, which will include the KeyType property
        var element = JsonSerializer.SerializeToElement(value, value.GetType(), serializerOptions);
        element.WriteTo(writer);
    }
}
