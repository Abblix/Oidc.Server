// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.Principal;

/// <summary>
/// How the claims of a validated ID Token become a <see cref="System.Security.Claims.ClaimsPrincipal"/>.
/// </summary>
public sealed class ClaimsPrincipalOptions
{
    /// <summary>
    /// The authentication type recorded on the identity.
    /// </summary>
    /// <remarks>
    /// It has to be set for the identity to count as authenticated: <c>ClaimsIdentity.IsAuthenticated</c> is
    /// false whenever the authentication type is null, whatever claims the identity holds. That is the one
    /// place where an empty-looking default would silently produce a principal every authorization check
    /// rejects.
    /// </remarks>
    public string AuthenticationType { get; set; } = "Abblix.Oidc.Client";

    /// <summary>
    /// Which claim answers <c>ClaimsPrincipal.Identity.Name</c>.
    /// </summary>
    /// <remarks>
    /// The subject rather than a display name. OIDC Core 1.0 section 5.7 says of <c>name</c> and its
    /// neighbours that they are "not guaranteed to be unique" and "must not be used as unique identifiers",
    /// while <c>sub</c> is what the specification defines as the stable identifier for the end-user at this
    /// issuer. A host that wants a friendlier name in the interface says so here.
    /// </remarks>
    public string NameClaimType { get; set; } = IanaClaimTypes.Sub;

    /// <summary>
    /// Which claim carries roles.
    /// </summary>
    /// <remarks>
    /// No standard names one: roles are whatever the provider was configured to issue, so the default is the
    /// conventional <c>role</c> and a host whose provider uses another name says which.
    /// </remarks>
    public string RoleClaimType { get; set; } = "role";
}
