// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Gives the tenant the current request was resolved to.
/// </summary>
/// <remarks>
/// Read on every call rather than captured, so a singleton holding it sees the tenant of whichever request is
/// running - the way <see cref="Common.Interfaces.IRequestInfoProvider"/> gives that request's address.
/// </remarks>
public interface ITenantAccessor
{
    /// <summary>
    /// The current request's tenant, or null when the request was not resolved to one.
    /// </summary>
    TenantContext? Current { get; }
}
