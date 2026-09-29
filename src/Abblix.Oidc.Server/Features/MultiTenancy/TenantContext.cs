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
/// The tenant a request was resolved to.
/// </summary>
/// <remarks>
/// Carries the whole definition, since what a request needs of its tenant is read synchronously while the
/// catalog that holds it is asynchronous.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantContext
{
    /// <summary>
    /// The tenant the request belongs to.
    /// </summary>
    public required TenantDefinition Tenant { get; init; }
}
