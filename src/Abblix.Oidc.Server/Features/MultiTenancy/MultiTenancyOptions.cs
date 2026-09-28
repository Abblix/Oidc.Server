// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The tenants a deployment serves and how a request is resolved to one of them.
/// </summary>
public sealed class MultiTenancyOptions
{
    /// <summary>
    /// The path segment that introduces a tenant, as <c>t</c> in <c>/t/{tenant}/connect/token</c>.
    /// </summary>
    public const string DefaultPathSegment = "t";

    /// <summary>
    /// The tenants this deployment serves.
    /// </summary>
    public List<TenantDefinition> Tenants { get; set; } = [];

    /// <summary>
    /// The path segment that introduces a tenant in a request path, or null to resolve tenants by host name
    /// only.
    /// </summary>
    public string? PathSegment { get; set; } = DefaultPathSegment;
}
