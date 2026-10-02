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
/// Readies what a tenant needs before the server first serves it, as the first key it signs with.
/// </summary>
/// <remarks>
/// The catalog hands over the tenants of one reading it has not served before, after the checks pass them, and
/// serves each once it is readied, so its first request finds what was readied. A tenant not readied is left out
/// of that reading and logged, and handed over again at the next one; a tenant the settings declare that is not
/// readied on the reading the server starts with refuses the start. The openings of one reading share one refresh
/// period, and the token is canceled when it runs out, except on that reading for the tenants the settings declare,
/// since the start waits for all of them.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantOpening
{
    /// <summary>
    /// Readies <paramref name="tenants"/> to be served, each one on its own, so one that fails leaves the others
    /// ready.
    /// </summary>
    /// <param name="tenants">The tenants about to be served for the first time.</param>
    /// <param name="cancellationToken">Cancels the opening.</param>
    /// <returns>Why each tenant that could not be readied was not, by its id; the others are ready.</returns>
    Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        CancellationToken cancellationToken);
}
