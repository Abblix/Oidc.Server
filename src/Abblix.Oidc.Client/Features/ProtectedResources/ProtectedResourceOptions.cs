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


namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// Which protected resource an HTTP client talks to, and what it needs to get in.
/// </summary>
public sealed class ProtectedResourceOptions
{
    /// <summary>
    /// The resource this client calls, as an absolute HTTPS address.
    /// </summary>
    /// <remarks>
    /// One value doing three jobs, which is why it is singular. It is the RFC 8707 section 2 resource
    /// indicator a host sends on the authorization request so the provider can audience-restrict the token;
    /// it is the boundary beyond which this client will not send that token; and it is what a later
    /// sender-constrained layer will key an audience on.
    /// Singular rather than a list because a list under one registration means one token spent at several
    /// audiences, which is the arrangement RFC 8707 exists to end. A host calling two APIs registers two
    /// clients.
    /// </remarks>
    public Uri? Resource { get; set; }

    /// <summary>
    /// The scopes this resource needs, passed to the token source so it can tell which token to hand over.
    /// </summary>
    public IReadOnlyCollection<string> Scopes { get; set; } = [];
}
