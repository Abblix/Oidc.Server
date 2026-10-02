// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Frozen;
using System.Text;
using Abblix.Oidc.Server.Common.Interfaces;
using Google.Protobuf;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides functionality to serialize and deserialize objects to and from Protocol Buffer binary representations.
/// Implements the <see cref="IBinarySerializer" /> interface using Google.Protobuf for efficient serialization.
/// </summary>
/// <remarks>
/// This serializer supports only specific OIDC storage types that have protobuf definitions and mappers.
/// Attempting to serialize unsupported types will throw InvalidOperationException.
/// </remarks>
public class ProtobufSerializer : IBinarySerializer
{
    /// <summary>
    /// The codec of each stored type, keyed by that type.
    /// </summary>
    private static readonly FrozenDictionary<Type, ProtobufCodec> Codecs = MappedProtobufCodecs.All
        .Concat(StoredProtobufCodecs.All)
        .ToFrozenDictionary(codec => codec.ValueType);

    /// <summary>
    /// Serializes an object to a binary representation using Protocol Buffers.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="obj">The object to serialize.</param>
    /// <returns>A byte array representing the serialized object.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the type is not supported for protobuf serialization.</exception>
    public byte[] Serialize<T>(T obj)
    {
        // Handle primitive string type directly
        if (obj is string str)
            return Encoding.UTF8.GetBytes(str);

        if (obj is null || CodecOf(obj.GetType()) is not { } codec)
        {
            throw new InvalidOperationException(
                $"Type {typeof(T).FullName} is not supported for protobuf serialization. " +
                "Only OIDC storage types with protobuf definitions are supported.");
        }

        return codec.ToMessage(obj).ToByteArray();
    }

    /// <summary>
    /// The codec serving a value of <paramref name="runtimeType"/>: its own, or else the one of the nearest base
    /// type that has one, as a type pattern would match a derived value.
    /// </summary>
    private static ProtobufCodec? CodecOf(Type runtimeType)
    {
        for (var type = runtimeType; type != null; type = type.BaseType)
        {
            if (Codecs.TryGetValue(type, out var codec))
                return codec;
        }

        return null;
    }

    /// <summary>
    /// Deserializes a binary representation to an object using Protocol Buffers.
    /// </summary>
    /// <typeparam name="T">The type of the object to deserialize into.</typeparam>
    /// <param name="bytes">The binary representation to deserialize from.</param>
    /// <returns>The deserialized object of type <typeparamref name="T" />.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the type is not supported for protobuf deserialization.</exception>
    public T? Deserialize<T>(byte[] bytes)
    {
        if (bytes.Length == 0)
            return default;

        var targetType = typeof(T);

        // Handle primitive string type directly
        if (targetType == typeof(string))
            return (T)(object)Encoding.UTF8.GetString(bytes);

        if (!Codecs.TryGetValue(targetType, out var codec))
        {
            throw new InvalidOperationException(
                $"Type {targetType.FullName} is not supported for protobuf deserialization. " +
                "Only OIDC storage types with protobuf definitions are supported.");
        }

        return (T?)codec.FromBytes(bytes);
    }
}
