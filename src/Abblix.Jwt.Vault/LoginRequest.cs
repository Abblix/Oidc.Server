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

using System.Text.Json.Serialization;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Body of a login against the Kubernetes auth method: the projected service-account token proves the pod,
/// the role names what the pod becomes.
/// </summary>
internal sealed record KubernetesLoginRequest
{
    /// <summary>Name of the Vault role to log in as.</summary>
    [JsonPropertyName("role")]
    public required string Role { get; init; }

    /// <summary>The projected service-account token, read from its file at the moment of login.</summary>
    [JsonPropertyName("jwt")]
    public required string Jwt { get; init; }
}

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

