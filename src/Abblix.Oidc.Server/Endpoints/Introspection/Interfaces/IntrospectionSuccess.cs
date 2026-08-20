// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.ClientInformation;


namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Server-side model of the introspection response defined by RFC 7662 §2.2: a Boolean
/// <c>active</c> flag and, when active, the token's metadata claims. Hosts may extend the
/// JSON via additional top-level members; cross-domain extensions should be listed in the
/// IANA "OAuth Token Introspection Response" registry (RFC 7662 §3.1).
/// </summary>
public record IntrospectionSuccess(bool Active, JsonObject? Claims, ClientInfo ClientInfo)
{
    /// <summary>
    /// Wire-level member names of the introspection response, as registered in the IANA
    /// "OAuth Token Introspection Response" registry (RFC 7662 §3.1).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>active</c> response member (RFC 7662 §2.2) reporting whether the token is
        /// currently active.</summary>
        public const string Active = "active";
    }

    /// <summary>
    /// RFC 7662 <c>active</c> field: <c>true</c> only if the token is currently valid and the
    /// caller is permitted to introspect it. <c>false</c> covers all other cases (expired,
    /// revoked, unknown, or not allowed) and per §2.2 is returned without disclosing why.
    /// </summary>
    public bool Active { get; } = Active;

    /// <summary>
    /// Token metadata claims (e.g. <c>scope</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>) when
    /// <see cref="Active"/> is <c>true</c>; otherwise <c>null</c>, in line with RFC 7662's
    /// guidance not to leak information about inactive tokens.
    /// </summary>
    public JsonObject? Claims { get; } = Claims;

    /// <summary>
    /// The authenticated client that requested the introspection. Not serialized into the response body; it selects
    /// the response format (plain JSON vs. a signed/encrypted JWT per RFC 9701).
    /// </summary>
    public ClientInfo ClientInfo { get; } = ClientInfo;
}
