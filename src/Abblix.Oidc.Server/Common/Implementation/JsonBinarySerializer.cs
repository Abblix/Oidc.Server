// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using System.Text.Json;
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Common.Implementation;

/// <summary>
/// Provides functionality to serialize and deserialize objects to and from JSON binary representations.
/// Implements the <see cref="IBinarySerializer"/> interface using the System.Text.Json library for serialization.
/// </summary>
public class JsonBinarySerializer(Encoding? encoding = null, JsonSerializerOptions? options = null) : IBinarySerializer
{
    private readonly Encoding _encoding = encoding ?? Encoding.UTF8;

    /// <summary>
    /// Serializes an object to a binary representation in JSON format.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="obj">The object to serialize into JSON format.</param>
    /// <returns>A byte array representing the serialized object in JSON format.</returns>
    public byte[] Serialize<T>(T obj)
    {
        var json = JsonSerializer.Serialize(obj, options);
        return _encoding.GetBytes(json);
    }

    /// <summary>
    /// Deserializes a binary representation of a JSON object to its original type.
    /// </summary>
    /// <typeparam name="T">The type of the object to deserialize into.</typeparam>
    /// <param name="bytes">The binary representation of the JSON object to deserialize.</param>
    /// <returns>The deserialized object of type <typeparamref name="T"/>.</returns>
    public T? Deserialize<T>(byte[] bytes)
    {
        var json = _encoding.GetString(bytes);
        return JsonSerializer.Deserialize<T>(json, options);
    }
}
