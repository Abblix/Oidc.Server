// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Microsoft.Extensions.Configuration;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Flat configuration DTO for a <see cref="JsonWebKeySet"/>, mirroring RFC 7517 Section 5
/// (a JSON object with a single <c>keys</c> array). See <see cref="JsonWebKeySettings"/>
/// for the per-key DTO and the design rationale.
/// </summary>
public sealed class JsonWebKeySetSettings
{
    /// <summary>The set of keys. Maps to the <c>keys</c> array per RFC 7517 §5.</summary>
    [ConfigurationKeyName("keys")]
    public List<JsonWebKeySettings>? Keys { get; init; }

    /// <summary>Maps this flat DTO to <see cref="JsonWebKeySet"/> by invoking
    /// <see cref="JsonWebKeySettings.ToJsonWebKey"/> on each entry.</summary>
    public JsonWebKeySet ToJsonWebKeySet() => new(
        (Keys ?? []).Select(k => k.ToJsonWebKey()).ToArray());

    /// <summary>Convenience implicit conversion to <see cref="JsonWebKeySet"/>;
    /// delegates to <see cref="ToJsonWebKeySet"/>.</summary>
    public static implicit operator JsonWebKeySet(JsonWebKeySetSettings settings)
        => settings.ToJsonWebKeySet();
}
