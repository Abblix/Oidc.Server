// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Jwt;

/// <summary>
/// A JWK Set's members as JSON carries them: a type without the set's converter, so reading it does not call back
/// in, read and written with the options of the keys it holds.
/// </summary>
/// <param name="Keys">The set's keys, or null when the set has no keys member.</param>
internal sealed record JsonWebKeySetDocument([property: JsonPropertyName(JsonWebKeySet.KeysMember)] JsonWebKey[]? Keys)
{
    /// <summary>
    /// Reads the set an object holds. A set without a <c>keys</c> member holds no keys, as its type says, rather than
    /// a null array a caller would enumerate.
    /// </summary>
    /// <remarks>
    /// RFC 7517 section 5: "Implementations SHOULD ignore JWKs within a JWK Set that use "kty" (key type) values that
    /// are not understood by them, that are missing required members, or for which values are out of the supported
    /// ranges." So one such key leaves the rest of an issuer's set usable, where a single key read on its own is
    /// still refused. A member that is not a JWK at all - not an object, a member named twice, a value that does not
    /// decode - is left out the same way: that is this library's choice, which the sentence does not make for it.
    /// </remarks>
    /// <param name="value">An object: the converter is its only caller, and a JSON null never reaches a converter.
    /// </param>
    /// <exception cref="JsonException">The <c>keys</c> member is not an array.</exception>
    public static JsonWebKeySet Read(JsonElement value)
    {
        if (!value.TryGetProperty(JsonWebKeySet.KeysMember, out var keys) || keys.ValueKind == JsonValueKind.Null)
            return new JsonWebKeySet([]);

        if (keys.ValueKind != JsonValueKind.Array)
            throw new JsonException($"The '{JsonWebKeySet.KeysMember}' member of a key set must be an array");

        return new JsonWebKeySet([.. keys.EnumerateArray().Select(Understood).OfType<JsonWebKey>()]);
    }

    /// <summary>
    /// The key <paramref name="member"/> holds, or null when it holds none or one this library does not understand:
    /// an unknown or missing key type, a malformed or repeated member, no public key members, or a curve it does not
    /// support. A JSON null deserializes to null and is left out with them.
    /// </summary>
    private static JsonWebKey? Understood(JsonElement member)
    {
        JsonWebKey? key;
        try
        {
            key = member.Deserialize<JsonWebKey>(JsonWebKeySerializerOptions.Instance);
        }
        catch (JsonException)
        {
            return null;
        }

        return key switch
        {
            { HasPublicKey: false } => null,
            EllipticCurveJsonWebKey ecKey when NamedCurves.Named(ecKey.Curve) is null => null,
            _ => key,
        };
    }

    /// <summary>
    /// Writes <paramref name="value"/> with its <c>keys</c> member.
    /// </summary>
    public static void Write(Utf8JsonWriter writer, JsonWebKeySet value)
        => JsonSerializer.Serialize(
            writer,
            new JsonWebKeySetDocument(value.Keys),
            JsonWebKeySerializerOptions.Instance);
}
