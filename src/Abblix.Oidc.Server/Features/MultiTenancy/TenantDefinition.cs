// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// A tenant this deployment serves: its issuer, and the host names that reach it.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantDefinition
{
    /// <summary>
    /// The identifier the tenant is registered under. It is also the path segment that names the tenant when
    /// requests reach it by path, so it is made of URL-unreserved characters only.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// The tenant's issuer identifier, as it appears in every token the tenant issues and in its discovery
    /// document.
    /// </summary>
    /// <remarks>
    /// Declared rather than derived from the request, so a tenant has one issuer whichever host or path reached
    /// it, and a request cannot make up another one by what it puts in its Host header.
    /// </remarks>
    public required string Issuer { get; init; }

    /// <summary>
    /// The host names whose requests belong to this tenant, without a port, compared without regard to case or
    /// a trailing dot. A host listed here is bound to the tenant, and a path naming another tenant on it is not
    /// followed.
    /// </summary>
    public IReadOnlyList<string> Hosts { get; init; } = [];
}
