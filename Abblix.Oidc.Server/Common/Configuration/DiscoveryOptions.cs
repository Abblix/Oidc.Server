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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Defines discovery endpoint options.
/// </summary>
public class DiscoveryOptions
{
	/// <summary>
	/// Allows exposing exact paths to OIDC endpoints via discovery manifest.
	/// </summary>
    public bool AllowEndpointPathsDiscovery { get; set; } = true;

    /// <summary>
    /// RFC 8705: Optional mTLS endpoint aliases to advertise.
    /// Configure with absolute URIs hosted on an mTLS-enabled origin.
    /// </summary>
    public MtlsAliasesOptions? MtlsEndpointAliases { get; set; }

    /// <summary>
    /// RFC 8705: Optional base URI for computing mTLS endpoint aliases automatically.
    /// If set, and a specific alias is not provided, discovery will derive the alias by
    /// taking the standard endpoint path and applying this base URI (scheme/host/port and optional base path).
    /// </summary>
    public Uri? MtlsBaseUri { get; set; }
}
