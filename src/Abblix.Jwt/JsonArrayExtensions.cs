// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Conversion helpers between a raw <see cref="JsonArray"/> wire form and a sequence of
/// <see cref="AuthorizationDetail"/> wrappers. Parallels <see cref="JsonObjectExtensions"/>
/// for object-shaped claims; here the shape is a JSON array and each element is a wrapper
/// over its underlying <see cref="JsonNode"/>.
/// </summary>
/// <remarks>
/// The raw <see cref="JsonArray"/> remains the source of truth - member order and type-specific
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
    /// nodes - read-through is byte-exact, and any property-setter calls mutate the underlying
    /// array in place.
    /// </summary>
    /// <param name="jsonArray">The raw array, or <c>null</c>.</param>
    /// <returns>A wrapper array, or <c>null</c> when the input is <c>null</c>.</returns>
    /// <remarks>
    /// The attribute states one half of the sentence above in the type system: never null out for an
    /// input that was not. The other half, null in null out, is not expressible there and is pinned by a
    /// test instead.
    ///
    /// Without it a caller holding a non-null array still gets a nullable result, and the way that gets
    /// silenced is a null-forgiving operator - which keeps compiling after the guard it depends on is
    /// moved or deleted, asserting something no longer true. With it the compiler carries the claim and
    /// re-checks it at every call site.
    /// </remarks>
    [return: NotNullIfNotNull(nameof(jsonArray))]
    public static AuthorizationDetail[]? ToTypedArray(this JsonArray? jsonArray)
    {
        return jsonArray?
            .Select(node => node is JsonObject obj ? new AuthorizationDetail(obj) : null)
            .OfType<AuthorizationDetail>()
            .ToArray();
    }
}
