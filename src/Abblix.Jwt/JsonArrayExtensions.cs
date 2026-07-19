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

using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Conversion helpers between a raw <see cref="JsonArray"/> wire form and a sequence of
/// <see cref="AuthorizationDetail"/> wrappers. Parallels <see cref="JsonObjectExtensions"/>
/// for object-shaped claims; here the shape is a JSON array and each element is a wrapper
/// over its underlying <see cref="JsonNode"/>.
/// </summary>
/// <remarks>
/// The raw <see cref="JsonArray"/> remains the source of truth — member order and type-specific
/// payload survive the authorize → code → token round-trip byte-exact because no typed
/// deserialise / re-serialise cycle ever runs over the wrapped nodes.
/// </remarks>
public static class JsonArrayExtensions
{
    /// <summary>
    /// Builds a fresh <see cref="JsonArray"/> from a sequence of <see cref="AuthorizationDetail"/>
    /// wrappers, deep-cloning each entry's underlying <see cref="AuthorizationDetail.Json"/> so
    /// the resulting array is independent of the sources and can attach to a different parent
    /// (JSON nodes may have only one parent at a time).
    /// </summary>
    /// <param name="details">The wrapper sequence, or <c>null</c>.</param>
    /// <returns>A fresh <see cref="JsonArray"/>, or <c>null</c> when the input is <c>null</c>.</returns>
    public static JsonArray? ToRawJsonArray(this IEnumerable<AuthorizationDetail>? details)
    {
        if (details is null) return null;

        var array = new JsonArray();
        foreach (var detail in details)
        {
            array.Add(detail.Json.DeepClone());
        }
        return array;
    }

    /// <summary>
    /// Wraps each non-null element of a raw <see cref="JsonArray"/> as an
    /// <see cref="AuthorizationDetail"/>. The wrappers share references with the source array's
    /// nodes — read-through is byte-exact, and any property-setter calls mutate the underlying
    /// array in place.
    /// </summary>
    /// <param name="jsonArray">The raw array, or <c>null</c>.</param>
    /// <returns>A wrapper array, or <c>null</c> when the input is <c>null</c>.</returns>
    public static AuthorizationDetail[]? ToTypedArray(this JsonArray? jsonArray)
    {
        return jsonArray?
            .Select(node => node is JsonObject obj ? new AuthorizationDetail(obj) : null)
            .OfType<AuthorizationDetail>()
            .ToArray();
    }
}
