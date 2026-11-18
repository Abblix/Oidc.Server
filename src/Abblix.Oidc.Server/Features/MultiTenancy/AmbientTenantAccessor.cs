// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The tenant of the innermost <see cref="TenantScope"/> entered, for a server composed without a web host; a web
/// host's transport replaces it with one that also reads the tenant the request was resolved to.
/// </summary>
public sealed class AmbientTenantAccessor : ITenantAccessor
{
    /// <inheritdoc />
    public TenantContext? Current => TenantScope.Current;
}
