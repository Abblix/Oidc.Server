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

using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// A composite serializer that tries Protocol Buffers first, then falls back to JSON for unsupported types.
/// </summary>
/// <param name="logger">The logger for recording fallback warnings.</param>
/// <param name="protobufSerializer">The Protocol Buffers serializer.</param>
/// <param name="jsonSerializer">The JSON serializer fallback.</param>
public class CompositeBinarySerializer(
    ILogger<CompositeBinarySerializer> logger,
    [FromKeyedServices(nameof(ProtobufSerializer))] IBinarySerializer protobufSerializer,
    [FromKeyedServices(nameof(JsonBinarySerializer))] IBinarySerializer jsonSerializer) : IBinarySerializer
{
    /// <summary>
    /// Serializes an object using Protocol Buffers if supported, otherwise falls back to JSON.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="obj">The object to serialize.</param>
    /// <returns>A byte array representing the serialized object.</returns>
    public byte[] Serialize<T>(T obj)
    {
        try
        {
            return protobufSerializer.Serialize(obj);
        }
        catch (InvalidOperationException)
        {
            logger.LogWarning(
                "Type {TypeName} is not supported for protobuf serialization, falling back to JSON",
                typeof(T).FullName);
            return jsonSerializer.Serialize(obj);
        }
    }

    /// <summary>
    /// Deserializes a binary representation using Protocol Buffers if supported, otherwise falls back to JSON.
    /// </summary>
    /// <typeparam name="T">The type of the object to deserialize into.</typeparam>
    /// <param name="bytes">The binary representation to deserialize from.</param>
    /// <returns>The deserialized object of type <typeparamref name="T" />.</returns>
    public T? Deserialize<T>(byte[] bytes)
    {
        try
        {
            return protobufSerializer.Deserialize<T>(bytes);
        }
        catch (InvalidOperationException)
        {
            logger.LogWarning(
                "Type {TypeName} is not supported for protobuf deserialization, falling back to JSON",
                typeof(T).FullName);
            return jsonSerializer.Deserialize<T>(bytes);
        }
    }
}
