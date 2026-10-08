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
/// Lets go of what a tenant kept outside the server's memory once the tenant is released, as the streams a
/// transmitter stored for it.
/// </summary>
/// <remarks>
/// The catalog of this instance hands over the tenants one reading releases, all at once, so a closing reads a store
/// the tenants share once for all of them. Each tenant is released at the first reading at least one refresh period
/// after a reading first found it gone from the store, in the definition last served for that creation, or the one it
/// was first listed in when it was never served. Each closing is called once per reading, with a token canceled one
/// refresh period after the call begins, and the reading waits for the call to end, so a closing heeds that token:
/// one that does not holds the reading, and every reading after it, for as long as it runs. One reading may release
/// two creations of one id, so a closing reports each tenant by the definition it was handed. A tenant a closing
/// reports, and every tenant of a call that throws, runs out of time or is stopped, is logged with its id and
/// generation and is not handed over again; the other closings still run. A tenant gone from the store while no
/// instance served it, as during a restart, is never listed by the new instance and so is never released or closed.
/// A tenant created again under the same id is a different creation, so closing the one released leaves what the new
/// one keeps alone.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantClosing
{
    /// <summary>
    /// Lets go of what each of <paramref name="tenants"/> kept, each one on its own, so one that fails leaves the
    /// others closed.
    /// </summary>
    /// <param name="tenants">The tenants released, each in the creation that was served.</param>
    /// <param name="cancellationToken">Cancels the closing.</param>
    /// <returns>Why each tenant that could not be closed, wholly or in part, was not, by the definition it was handed
    /// in; the others are closed.</returns>
    Task<IReadOnlyDictionary<TenantDefinition, Exception>> CloseAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        CancellationToken cancellationToken);
}
