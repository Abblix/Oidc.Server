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
/// Readies what a tenant needs before the server starts serving it, as the first key it signs with.
/// </summary>
/// <remarks>
/// The catalog opens each tenant of a reading after the checks pass it and before the reading is served, so the
/// tenant's first request finds what was readied. A tenant it cannot open is left out of that reading and logged,
/// and tried again at the next one; on the first reading, which the server starts with, the failure refuses the
/// start, as the store failing to answer does.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantOpening
{
    /// <summary>
    /// Readies <paramref name="tenant"/> to be served, doing nothing when it is ready already.
    /// </summary>
    /// <param name="tenant">The tenant about to be served.</param>
    /// <param name="cancellationToken">Cancels the opening.</param>
    Task OpenAsync(TenantDefinition tenant, CancellationToken cancellationToken);
}
