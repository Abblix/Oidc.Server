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
/// A tenant this deployment serves.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantDefinition
{
    /// <summary>
    /// The identifier the tenant is registered under.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// The tenant's issuer identifier, as it appears in every token the tenant issues and in its discovery
    /// document - and the address the tenant is served at.
    /// </summary>
    /// <remarks>
    /// A request belongs to the tenant whose issuer names its host and the longest start of its path, so a
    /// tenant has one address, and OpenID Connect Discovery 1.0 section 4.3 - the issuer is the address the
    /// discovery document was fetched from - holds by construction: <c>https://acme.example.com</c> serves a
    /// whole host, <c>https://auth.example.com/tenants/acme</c> a path on a shared one.
    /// </remarks>
    public required string Issuer { get; init; }
}
