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
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Common.Implementation;

/// <summary>
/// Provides functionality to serialize and deserialize objects to and from JSON binary representations.
/// Implements the <see cref="IBinarySerializer"/> interface using the System.Text.Json library for serialization.
/// </summary>
public class JsonBinarySerializer : IBinarySerializer
{
    public JsonBinarySerializer(Encoding? encoding = null, JsonSerializerOptions? options = null)
    {
        _encoding = encoding ?? Encoding.UTF8;
        _options = options;
    }

    private readonly Encoding _encoding;
    private readonly JsonSerializerOptions? _options;

    /// <summary>
    /// Serializes an object to a binary representation in JSON format.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="obj">The object to serialize into JSON format.</param>
    /// <returns>A byte array representing the serialized object in JSON format.</returns>
    public byte[] Serialize<T>(T obj)
    {
        var json = JsonSerializer.Serialize(obj, _options);
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
        return JsonSerializer.Deserialize<T>(json, _options);
    }
}
