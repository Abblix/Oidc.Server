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
/// Whether somebody answering for the deployment let a client in, which decides whether the server redirects the user
/// agent to its redirect URIs with an authorization error (RFC 9700 section 4.11.2).
/// </summary>
/// <remarks>
/// Decided once, when the client is created, and kept in its record, so every replica reading the client from a shared
/// store gives the same answer whatever settings it runs with. A client declared in the tenant settings is
/// <see cref="Reviewed"/> unless the host says otherwise; one registered dynamically while registration is open is
/// <see cref="Unreviewed"/>, and one registered while it is closed <see cref="Reviewed"/>. A client resolved from its
/// metadata document is <see cref="Unreviewed"/> unless the host lists the URLs it accepts documents from. A registrant
/// neither sets nor changes it: it is no registration metadata, and an RFC 7592 update keeps it.
/// <para>
/// A stored record naming no value is <see cref="Reviewed"/>, as every client of a record written before the member
/// existed was treated; a record naming one is read as named, by its member's
/// <see cref="JsonStringEnumMemberNameAttribute"/>.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ClientTrust>))]
public enum ClientTrust
{
    /// <summary>
    /// Somebody answering for the deployment let the client in, so its redirect URIs are trusted.
    /// </summary>
    [JsonStringEnumMemberName("reviewed")]
    Reviewed,

    /// <summary>
    /// The client let itself in, so the server answers its authorization errors itself rather than at its redirect
    /// URIs.
    /// </summary>
    [JsonStringEnumMemberName("unreviewed")]
    Unreviewed,
}
