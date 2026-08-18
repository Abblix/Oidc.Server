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

namespace Abblix.Jwt.Vault;

/// <summary>
/// Points the custodian at a HashiCorp Vault / OpenBao Transit secrets engine: where it is and how to
/// authenticate to it, and nothing about which keys to use. Which keys, and therefore whether their private
/// halves ever enter this process, is the placement choice that follows the custodian registration.
/// </summary>
public sealed class VaultTransitOptions
{
    /// <summary>Base URL of the Vault / OpenBao server, e.g. <c>http://127.0.0.1:8200</c>.</summary>
    public string Address { get; set; } = "http://127.0.0.1:8200";

    /// <summary>
    /// Auth token presented as the <c>X-Vault-Token</c> header, for a host that already has one and owns its
    /// lifetime. Source it from the environment or a secret store, never hardcode it. A production host
    /// normally configures <see cref="Authentication"/> instead and lets the package mint and renew the token
    /// itself; a minted token takes precedence over this value.
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// Makes the package log in to Vault itself - with the pod's Kubernetes service account or an AppRole -
    /// and keep the resulting token renewed for the process lifetime. Absent by default: a host that hands
    /// over <see cref="Token"/> keeps owning it.
    /// </summary>
    public VaultAuthenticationOptions? Authentication { get; set; }

    /// <summary>Mount path of the Transit engine (the default mount is <c>transit</c>).</summary>
    public string TransitMount { get; set; } = "transit";

    /// <summary>
    /// How long a pooled HTTP connection is reused before it is recycled. The Transit client is held long-lived by
    /// the singleton key store, so recycling connections lets it pick up DNS changes without handler rotation
    /// (default 2 minutes, matching the default IHttpClientFactory handler lifetime).
    /// </summary>
    public TimeSpan PooledConnectionLifetime { get; set; } = TimeSpan.FromMinutes(2);
}
