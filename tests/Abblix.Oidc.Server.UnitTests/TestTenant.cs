// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Moq;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// The tenant a test serves, as a double's setup matches it.
/// </summary>
public static class TestTenant
{
    /// <summary>
    /// Matches the test's own tenant by its id and no other, so a caller handing a double a tenant with another id
    /// gets nothing back and its test fails. Matched by id because a tenant read through the server is a new
    /// definition on each read.
    /// </summary>
    public static TenantDefinition Matched => Match.Create<TenantDefinition>(
        tenant => string.Equals(tenant.Id, TestIssuer.TenantId, StringComparison.Ordinal));
}
