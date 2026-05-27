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
using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Conversion helpers between a raw <see cref="JsonArray"/> wire form and a typed-array
/// projection. Parallels <see cref="JsonObjectExtensions"/> for object-shaped claims;
/// here the shape is a JSON array.
/// </summary>
/// <remarks>
/// Used by the structured-claim accessors (<c>JsonWebTokenPayload.AuthorizationDetailsRaw</c>
/// for RFC 9396, and any future array-shaped claim) so the raw <see cref="JsonArray"/> remains
/// the source of truth — preserving member order and type-specific payload byte-exact across
/// the authorize → code → token round-trip — while typed projections are produced on demand
/// for code consumption.
/// </remarks>
public static class JsonArrayExtensions
{
    /// <summary>
    /// Serialises a typed sequence into a fresh <see cref="JsonArray"/> via the default
    /// <see cref="JsonSerializer"/>. The result is a new tree owned by the caller — no
    /// references shared with the input.
    /// </summary>
    /// <typeparam name="T">The element type to serialise.</typeparam>
    /// <param name="values">The sequence, or <c>null</c>.</param>
    /// <returns>A fresh <see cref="JsonArray"/>, or <c>null</c> when the input is <c>null</c>.</returns>
    public static JsonArray? ToRawJsonArray<T>(this IEnumerable<T>? values)
    {
        if (values is null) return null;

        var array = new JsonArray();
        foreach (var value in values)
        {
            array.Add(JsonSerializer.SerializeToNode(value));
        }
        return array;
    }

    /// <summary>
    /// Projects a raw <see cref="JsonArray"/> into a typed <typeparamref name="T"/>[] for code
    /// consumption. Each element is deserialised independently via the default
    /// <see cref="JsonSerializer"/>; entries that fail to materialise (null nodes, or nodes
    /// that do not match the target type) are skipped.
    /// </summary>
    /// <typeparam name="T">The element type to deserialise into.</typeparam>
    /// <param name="jsonArray">The raw array, or <c>null</c>.</param>
    /// <returns>A typed array, or <c>null</c> when the input is <c>null</c>.</returns>
    public static T[]? ToTypedArray<T>(this JsonArray? jsonArray)
    {
        return jsonArray?
            .Select(node => node is null ? default : node.Deserialize<T>())
            .OfType<T>()
            .ToArray();
    }
}
