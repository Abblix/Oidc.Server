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
/// The catalog of this instance hands over each tenant it releases, one refresh period after a reading first found it
/// gone from the store, in the definition last served for that creation, and waits within that reading for up to
/// one refresh period for each call. A closing that fails, runs out of time or is stopped is logged with the
/// tenant's id and is not handed over again; the other tenants and closings still run. A tenant gone from the store
/// while no instance served it, as during a restart, is never listed by the new instance and so is never released or
/// closed. A tenant created again under the same id is a different creation, so closing the one released leaves what
/// the new one keeps alone.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantClosing
{
    /// <summary>
    /// Lets go of what <paramref name="tenant"/> kept.
    /// </summary>
    /// <param name="tenant">The released tenant, in the creation that was served.</param>
    /// <param name="cancellationToken">Cancels the closing.</param>
    Task CloseAsync(TenantDefinition tenant, CancellationToken cancellationToken);
}
