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

namespace Abblix.Oidc.Server.AspNetCore.UnitTests;

/// <summary>
/// The tenant a test's request is served by, where the test is about something other than the tenants.
/// </summary>
internal static class TestTenantAccess
{
    /// <summary>The id of the tenant, which is also the partition of its keys.</summary>
    public const string Main = "main";

    private static readonly TenantContext MainContext = new()
    {
        Tenant = new TenantDefinition { Id = Main, Issuer = new Uri("https://auth.example.com") },
    };

    /// <summary>Tells every request it is served by the tenant <see cref="Main"/>.</summary>
    public static ITenantAccessor UnderMain => Mock.Of<ITenantAccessor>(accessor => accessor.Current == MainContext);
}
