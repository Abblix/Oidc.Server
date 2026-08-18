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

/// <summary>
/// The Kubernetes auth method: the pod proves who it is with the service-account token Kubernetes projected
/// into it, and Vault answers with a token for the named role.
/// </summary>
public sealed class KubernetesAuthenticationOptions
{
    /// <summary>Mount path of the Kubernetes auth method (the default mount is <c>kubernetes</c>).</summary>
    public string Mount { get; set; } = "kubernetes";

    /// <summary>
    /// Name of the Vault role to log in as. The role binds the service account and namespace to the policies
    /// the token receives, so it is the one value that has no default.
    /// </summary>
    public string? Role { get; set; }

    /// <summary>
    /// Path of the projected service-account token file. The default is where Kubernetes mounts it. The file
    /// is read on every login, never cached: the kubelet rotates the token at 80% of its lifetime, and the
    /// application is the one responsible for picking the rotation up.
    /// </summary>
    public string ServiceAccountTokenPath { get; set; } = "/var/run/secrets/kubernetes.io/serviceaccount/token";
}

/// <summary>
/// The AppRole auth method: the host proves who it is with a role and secret identifier pair.
/// </summary>
/// <remarks>
/// The role behind these identifiers must issue a service token without a use limit
/// (<c>token_num_uses=0</c>): every Transit call spends a use invisibly, so a limited token dies mid-flight
/// with nothing naming the limit. And every login consumes a <c>secret_id</c> use, including logins retried
/// after a lost response, so a bounded <c>secret_id_num_uses</c> runs out on schedule rather than on error.
/// </remarks>
public sealed class AppRoleAuthenticationOptions
{
    /// <summary>Mount path of the AppRole auth method (the default mount is <c>approle</c>).</summary>
    public string Mount { get; set; } = "approle";

    /// <summary>Identifier of the AppRole to log in as.</summary>
    public string? RoleId { get; set; }

    /// <summary>
    /// The secret half of the pair. Source it from a secret store or a mounted secret, never hardcode it.
    /// It is re-read from configuration on every login, so a rotated value delivered through configuration
    /// reload is picked up without a restart.
    /// </summary>
    public string? SecretId { get; set; }
}
