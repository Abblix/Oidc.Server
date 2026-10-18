// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;

namespace Abblix.Jwt;

/// <summary>
/// Reads and writes a key as its concrete subtype, so the subtype's own attributes decide its members and
/// <c>kty</c> is written once, by the subtype.
/// </summary>
internal static class JsonWebKeySubtypes
{
    /// <summary>
    /// Reads <paramref name="json"/> as the subtype <paramref name="keyType"/> names: <see cref="RsaJsonWebKey"/>,
    /// <see cref="EllipticCurveJsonWebKey"/> or <see cref="OctetJsonWebKey"/>.
    /// </summary>
    /// <exception cref="JsonException">The key type is not one of the three.</exception>
    public static JsonWebKey? Deserialize(string keyType, string json, JsonSerializerOptions options) => keyType switch
    {
        JsonWebKeyTypes.Rsa => JsonSerializer.Deserialize<RsaJsonWebKey>(json, options),
        JsonWebKeyTypes.EllipticCurve => JsonSerializer.Deserialize<EllipticCurveJsonWebKey>(json, options),
        JsonWebKeyTypes.Octet => JsonSerializer.Deserialize<OctetJsonWebKey>(json, options),
        _ => throw new JsonException($"Unknown key type: {keyType}"),
    };

    /// <summary>Writes <paramref name="value"/> in its concrete subtype's shape.</summary>
    public static void Serialize(Utf8JsonWriter writer, JsonWebKey value, JsonSerializerOptions options)
    {
        // Serialize the concrete type, which will include the KeyType property
        var element = JsonSerializer.SerializeToElement(value, value.GetType(), options);
        element.WriteTo(writer);
    }
}
