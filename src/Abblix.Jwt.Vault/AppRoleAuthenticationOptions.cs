// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault;

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
