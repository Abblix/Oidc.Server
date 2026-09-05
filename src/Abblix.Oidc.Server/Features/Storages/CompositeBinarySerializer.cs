// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
public partial class CompositeBinarySerializer(
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
        catch (InvalidOperationException ex)
        {
            LogProtobufSerializeFallback(ex, typeof(T).FullName);
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
        catch (InvalidOperationException ex)
        {
            LogProtobufDeserializeFallback(ex, typeof(T).FullName);
            return jsonSerializer.Deserialize<T>(bytes);
        }
    }
}
