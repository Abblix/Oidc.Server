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
