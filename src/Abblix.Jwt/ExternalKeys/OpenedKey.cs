// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// One opened entry: the key itself, when it was minted, which is what orders the set, and the id it is
/// stored under, which is what retires it.
/// </summary>
internal sealed record OpenedKey(string Id, JsonWebKey Key, DateTimeOffset CreatedAt)
{
    /// <summary>Whether the key was adopted from the host rather than minted by the ring.</summary>
    public bool IsAdopted => AdoptedEntries.IsAdopted(Id);

    /// <summary>
    /// Whether a key may serve a role: either it names that role, or it names none and is therefore unrestricted.
    /// </summary>
    /// <remarks>
    /// RFC 7517 section 4.2 makes <c>use</c> OPTIONAL and single-valued, so a key permitted to both sign and
    /// encrypt is expressed by omitting the member, never by a multi-valued one. Reading an absent <c>use</c> as
    /// "no role" rather than "any role" would drop exactly those keys, and silently: they match no role, so they
    /// leave the published set without anything reporting a loss. A certificate permitting both signing and
    /// encipherment produces precisely such a key.
    /// </remarks>
    public static bool Serves(JsonWebKey key, string usage) => key.Usage is null || key.Usage == usage;
}
