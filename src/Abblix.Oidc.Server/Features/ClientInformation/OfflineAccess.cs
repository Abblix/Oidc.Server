// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Whether a client may receive offline access, the refresh tokens the <c>offline_access</c> scope asks for, and
/// whether its authorization request has to ask for consent with <c>prompt=consent</c> to receive it.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0, section 11, requires <c>prompt=consent</c> for offline access "unless other conditions
/// for processing the request permitting offline access to the requested resources are in place", and
/// <see cref="Allowed"/> is where the host states such conditions for a client. Either way, consent to offline access
/// is the end user's, as the host's consent provider reports it.
/// <para>
/// On the wire it is the <c>offline_access</c> client registration parameter, a server extension to RFC 7591
/// metadata, which names each value as its member's <see cref="JsonStringEnumMemberNameAttribute"/> says.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<OfflineAccess>))]
public enum OfflineAccess
{
    /// <summary>
    /// The client receives no offline access: it is refused where the request would otherwise receive it, and is
    /// issued no refresh token, nor renews the ones it holds.
    /// </summary>
    [JsonStringEnumMemberName("disabled")]
    Disabled,

    /// <summary>
    /// The client receives offline access from an authorization request that asks for consent with
    /// <c>prompt=consent</c>; a request that does not has its <c>offline_access</c> scope ignored.
    /// </summary>
    [JsonStringEnumMemberName("consent_required")]
    ConsentRequired,

    /// <summary>
    /// The client receives offline access without asking for consent with <c>prompt=consent</c>. It is host-side
    /// configuration only: a client registering itself cannot set it.
    /// </summary>
    [JsonStringEnumMemberName("allowed")]
    Allowed,
}
