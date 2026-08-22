// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Body of a login against the AppRole auth method: the role and secret identifier pair.
/// </summary>
internal sealed record AppRoleLoginRequest
{
    /// <summary>Identifier of the AppRole to log in as.</summary>
    [JsonPropertyName("role_id")]
    public required string RoleId { get; init; }

    /// <summary>The secret half of the pair.</summary>
    [JsonPropertyName("secret_id")]
    public required string SecretId { get; init; }
}
