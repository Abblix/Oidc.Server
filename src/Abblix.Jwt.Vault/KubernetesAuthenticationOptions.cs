// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault;

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
