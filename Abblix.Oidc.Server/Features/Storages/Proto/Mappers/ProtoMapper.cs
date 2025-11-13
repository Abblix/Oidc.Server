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

using Google.Protobuf;
using Google.Protobuf.Collections;

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Common extension methods for protobuf message mapping.
/// </summary>
internal static class ProtoMapper
{
    /// <summary>
    /// Converts a protobuf ByteString to a Guid.
    /// </summary>
    /// <param name="bytes">The ByteString containing the Guid bytes (must be 16 bytes).</param>
    /// <returns>Guid reconstructed from the byte array.</returns>
    public static Guid ToGuid(this ByteString bytes) => new(bytes.ToByteArray());

    /// <summary>
    /// Converts a Guid to protobuf ByteString representation.
    /// </summary>
    /// <param name="guid">The Guid to convert.</param>
    /// <returns>ByteString containing the Guid bytes (16 bytes).</returns>
    public static ByteString ToProto(this Guid guid) => ByteString.CopyFrom(guid.ToByteArray());

    /// <summary>
    /// Adds elements to a RepeatedField if the source is not null.
    /// </summary>
    public static void AddIfNotNull<T>(this RepeatedField<T> target, IEnumerable<T>? source)
    {
        if (source != null)
            target.AddRange(source);
    }

    /// <summary>
    /// Adds transformed elements to a RepeatedField if the source is not null.
    /// </summary>
    public static void AddIfNotNull<T, T2>(this RepeatedField<T2> target, IEnumerable<T>? source, Func<T, T2> selector)
    {
        if (source != null)
            target.AddRange(source.Select(selector));
    }

    /// <summary>
    /// Converts a RepeatedField to an array, or null if empty.
    /// </summary>
    public static string[]? GetArray(this RepeatedField<string> field)
        => field.Count > 0 ? field.ToArray() : null;

    /// <summary>
    /// Converts a RepeatedField to an array with transformation, or null if empty.
    /// </summary>
    public static T2[]? GetArray<T, T2>(this RepeatedField<T> field, Func<T, T2> selector)
        => field.Count > 0 ? field.Select(selector).ToArray() : null;

    /// <summary>
    /// Returns a string value if present, or null if the optional field is not set.
    /// </summary>
    public static string? GetString(string value, bool hasValue)
        => hasValue ? value : null;

    /// <summary>
    /// Returns a Uri value if present, or null if the optional field is not set.
    /// </summary>
    public static Uri? GetUri(string value, bool hasValue)
        => hasValue ? new Uri(value) : null;
}
