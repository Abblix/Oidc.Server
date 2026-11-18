// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// The Minimal API adapter's registration leaves its own mark for the MVC adapter's conflict check, so the check
/// does not depend on which of the contracts this adapter serves happen to be declared in its assembly.
/// </summary>
public class AdapterMarkerTests
{
    [Fact]
    public void TheMinimalApiAdapterRegistration_LeavesItsMark()
    {
        var services = new ServiceCollection();
        services.AddOidcMinimalApi();

        Assert.Contains(services, descriptor => descriptor.ServiceType == typeof(MinimalApiAdapterMarker));
    }
}
