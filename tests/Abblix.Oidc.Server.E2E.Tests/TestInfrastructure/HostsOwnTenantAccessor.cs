// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// A tenant accessor of the host's own, which tells the tenant of a request without the server's middleware.
/// </summary>
internal sealed class HostsOwnTenantAccessor : ITenantAccessor
{
    /// <inheritdoc />
    public TenantContext? Current => null;
}
