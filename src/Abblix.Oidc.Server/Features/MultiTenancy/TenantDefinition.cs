// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// A tenant this deployment serves, and the host names that reach it.
/// </summary>
public sealed record TenantDefinition
{
    /// <summary>
    /// The identifier the tenant is registered under. It is also the path segment that names the tenant when
    /// requests reach it by path, so it holds no slash.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// The host names whose requests belong to this tenant, compared without regard to case. A host listed here
    /// is bound to the tenant, and a path naming another tenant on it is not followed.
    /// </summary>
    public string[] Hosts { get; init; } = [];
}
