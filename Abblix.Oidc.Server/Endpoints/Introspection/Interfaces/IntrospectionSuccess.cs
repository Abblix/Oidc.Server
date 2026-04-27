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

using System.Text.Json.Nodes;


namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Server-side model of the introspection response defined by RFC 7662 §2.2: a Boolean
/// <c>active</c> flag and, when active, the token's metadata claims. Hosts may extend the
/// JSON via additional top-level members; cross-domain extensions should be listed in the
/// IANA "OAuth Token Introspection Response" registry (RFC 7662 §3.1).
/// </summary>
public record IntrospectionSuccess(bool Active, JsonObject? Claims)
{
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
}
