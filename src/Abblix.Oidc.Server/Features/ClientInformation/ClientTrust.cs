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
/// Whether the server trusts a client's redirect URIs, which decides whether it redirects the user agent there with an
/// authorization error. The vocabulary is that of <see href="https://datatracker.ietf.org/doc/html/rfc9700#section-4.11.2">RFC 9700 section 4.11.2</see>: the authorization server "needs to decide whether or not it
/// can trust the redirection URI", and "SHOULD only automatically redirect the user agent if it trusts the
/// redirection URI".
/// </summary>
/// <remarks>
/// Decided once, when the client is created, and kept in its record, so every replica reading the client from a shared
/// store gives the same answer whatever settings it runs with. A client declared in the tenant settings is
/// <see cref="Trusted"/> unless the host says otherwise; one registered dynamically while registration is open is
/// <see cref="Untrusted"/>, and one registered while it is closed <see cref="Trusted"/>. A client resolved from its
/// metadata document is <see cref="Untrusted"/> unless the host lists the URLs it accepts documents from. A registrant
/// neither sets nor changes it: it is no registration metadata, and an RFC 7592 update keeps it.
/// <para>
/// A stored record naming no value is <see cref="Trusted"/>, as every client of a record written before the member
/// existed was treated; a record naming one is read as named, by its member's
/// <see cref="JsonStringEnumMemberNameAttribute"/>.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ClientTrust>))]
public enum ClientTrust
{
    /// <summary>
    /// Somebody answering for the deployment let the client in, so the server trusts its redirect URIs and redirects
    /// an authorization error there: <see href="https://datatracker.ietf.org/doc/html/rfc9700#section-4.11.2">RFC 9700 section 4.11.2</see> has the server "only automatically redirect the user agent if it trusts the
    /// redirection URI".
    /// </summary>
    [JsonStringEnumMemberName("trusted")]
    Trusted,

    /// <summary>
    /// The client let itself in, such as one that registered itself while registration is open, so the server does not
    /// trust its redirect URIs and answers its authorization errors itself: <see href="https://datatracker.ietf.org/doc/html/rfc9700#section-4.11.2">RFC 9700 section 4.11.2</see> names an attacker who could
    /// "register a client via dynamic client registration" and send an erroneous request, "thus instructing the
    /// authorization server to redirect the user agent to its phishing site".
    /// </summary>
    [JsonStringEnumMemberName("untrusted")]
    Untrusted,
}
