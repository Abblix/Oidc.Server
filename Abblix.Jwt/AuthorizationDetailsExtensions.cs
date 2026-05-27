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
/// Conversion helpers between the raw <see cref="JsonArray"/> wire form of an RFC 9396
/// <c>authorization_details</c> array (the canonical storage carried through the
/// authorize → code → token pipeline) and the typed <see cref="AuthorizationDetail"/>[]
/// projection used by validators, host code, and tests.
/// </summary>
/// <remarks>
/// The wire form (<see cref="JsonArray"/>) is the source of truth: it preserves member order
/// and any type-specific payload byte-exact across persistence and emission. The typed
/// projection is a convenience for reads — each element is deserialised on demand into a
/// strongly-typed <see cref="AuthorizationDetail"/>. To replace the array in code (tests,
/// host-provided narrowing) construct a new <see cref="JsonArray"/> via
/// <see cref="ToRawJsonArray"/>; the next read through the typed accessor reflects the change.
/// </remarks>
public static class AuthorizationDetailsExtensions
{
    /// <summary>
    /// Serialises a typed <see cref="AuthorizationDetail"/> sequence into a raw
    /// <see cref="JsonArray"/> suitable for storage on
    /// <see cref="JsonWebTokenPayload"/> claims and the OIDC authorization pipeline.
    /// </summary>
    /// <param name="details">The typed sequence, or <c>null</c> when no
    /// <c>authorization_details</c> were requested.</param>
    /// <returns>A fresh <see cref="JsonArray"/> mirroring the input, or <c>null</c> when the
    /// input is <c>null</c>.</returns>
    public static JsonArray? ToRawJsonArray(this IEnumerable<AuthorizationDetail>? details)
    {
        if (details is null) return null;

        var array = new JsonArray();
        foreach (var detail in details)
        {
            array.Add(JsonSerializer.SerializeToNode(detail));
        }
        return array;
    }

    /// <summary>
    /// Projects a raw <see cref="JsonArray"/> of <c>authorization_details</c> entries into a
    /// typed <see cref="AuthorizationDetail"/>[] for code consumption. Each element is
    /// deserialised independently; <c>null</c> JSON entries are skipped.
    /// </summary>
    /// <param name="raw">The raw array, or <c>null</c>.</param>
    /// <returns>A typed array, or <c>null</c> when the input is <c>null</c>.</returns>
    public static AuthorizationDetail[]? ToTypedArray(this JsonArray? raw)
    {
        return raw?
            .Select(node => node?.Deserialize<AuthorizationDetail>())
            .OfType<AuthorizationDetail>()
            .ToArray();
    }
}
