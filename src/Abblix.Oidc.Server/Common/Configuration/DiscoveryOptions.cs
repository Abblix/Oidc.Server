// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// RFC 8414 §2.1: when enabled, the discovery document additionally carries a
    /// <c>signed_metadata</c> JWS whose payload is the same metadata set, signed with the
    /// authorization server's signing key. This lets relying parties verify the
    /// configuration's origin independently of the TLS layer (relevant behind CDNs, API
    /// gateways, or aggressive caches). Off by default: clients that do not validate the
    /// signature gain nothing from it, and an unconsumed field only adds payload weight.
    /// </summary>
    public bool SignedMetadata { get; set; }

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

    /// <summary>
    /// Optional ACR (Authentication Context Class Reference) values supported by this provider.
    /// These values represent authentication assurance levels that can be requested and achieved.
    /// If not set, no acr_values_supported will be included in the discovery document.
    /// </summary>
    public IEnumerable<string>? AcrValuesSupported { get; set; }
}
