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
/// <remarks>
/// <para>
/// Looks superficially replaceable by <c>[JsonPolymorphic(TypeDiscriminatorPropertyName = "kty")]</c>
/// + <c>[JsonDerivedType]</c>. It is not, because of how this hierarchy emits "kty" today:
/// each concrete subtype overrides <see cref="JsonWebKey.KeyType"/> with
/// <c>[JsonPropertyName("kty")]</c> and <c>[JsonInclude]</c>, which guarantees "kty" appears
/// both in polymorphic writes (<c>JsonSerializer.Serialize&lt;JsonWebKey&gt;(rsaKey)</c>) and in
/// direct concrete-type writes (<c>JsonSerializer.Serialize(rsaKey)</c> where the compile-time
/// type is <c>RsaJsonWebKey</c>).
/// </para>
/// <para>
/// Switching to <c>[JsonPolymorphic]</c> alone breaks one of those two scenarios:
/// </para>
/// <list type="bullet">
/// <item><description>Keep the derived <c>[JsonInclude]</c> override AND add <c>[JsonPolymorphic]</c>
/// → "kty" gets written twice in polymorphic context (once by STJ as the discriminator, once by
/// the derived property), producing invalid JSON.</description></item>
/// <item><description>Drop the derived <c>[JsonInclude]</c> override → "kty" disappears whenever a
/// concrete subtype is serialized directly, because <c>[JsonPolymorphic]</c> only writes the
/// discriminator when STJ sees the abstract base type.</description></item>
/// </list>
/// <para>
/// This converter bridges both write modes by always serializing through the concrete subtype's
/// own attribute set, so "kty" lands once regardless of the call site. A future replacement is
/// possible but must also touch every <c>KeyType</c> override and ship with a round-trip
/// regression test that covers polymorphic AND direct serialization paths.
/// </para>
/// </remarks>
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
            if (converter is JsonWebKeyConverter)
                continue;
            
            result.Converters.Add(converter);
        }

        return result;
    }

    /// <summary>
    /// Reads a <see cref="JsonWebKey"/> from the JSON payload, dispatching to the matching
    /// concrete subtype (<see cref="RsaJsonWebKey"/>, <see cref="EllipticCurveJsonWebKey"/>,
    /// or <see cref="OctetJsonWebKey"/>) based on the <c>kty</c> property.
    /// </summary>
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

    /// <summary>
    /// Writes a <see cref="JsonWebKey"/> to JSON in its concrete-subtype shape, so the
    /// resulting object includes the <c>kty</c> discriminator and every key-type-specific
    /// member.
    /// </summary>
    public override void Write(Utf8JsonWriter writer, JsonWebKey value, JsonSerializerOptions options)
    {
        var serializerOptions = CreateOptionsForDerivedType(options);

        // Serialize the concrete type, which will include the KeyType property
        var element = JsonSerializer.SerializeToElement(value, value.GetType(), serializerOptions);
        element.WriteTo(writer);
    }
}
