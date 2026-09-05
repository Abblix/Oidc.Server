// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault;

/// <summary>
/// Makes the package obtain its own Vault token by logging in against an auth method, and keep it alive:
/// renew before the lease ends, log in again when the lease cannot be extended further. Configuring this
/// section replaces a statically supplied <see cref="VaultTransitOptions.Token"/>; leaving it absent keeps
/// today's posture, where the host hands a token over and owns its lifetime.
/// </summary>
/// <remarks>
/// Exactly one of the method subsections must be set. The section is null when a host does not configure it -
/// there is deliberately no default instance, because an empty section and an absent one must stay
/// distinguishable for the feature to have an off switch.
/// </remarks>
public sealed class VaultAuthenticationOptions
{
    /// <summary>
    /// Log in with the pod's projected service-account token, which is the arrangement for a host running on
    /// Kubernetes: the kubelet rotates the file and this package re-reads it on every login.
    /// </summary>
    public KubernetesAuthenticationOptions? Kubernetes { get; set; }

    /// <summary>
    /// Log in with an AppRole's role and secret identifiers, which is the arrangement for a host outside
    /// Kubernetes or one whose Vault does not trust the cluster.
    /// </summary>
    public AppRoleAuthenticationOptions? AppRole { get; set; }
}
