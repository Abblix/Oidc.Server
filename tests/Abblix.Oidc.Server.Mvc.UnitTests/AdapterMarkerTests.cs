// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// The MVC adapter's registration leaves its own mark for the Minimal API adapter's conflict check, so the check
/// does not depend on which of the contracts this adapter serves happen to be declared in its assembly.
/// </summary>
public class AdapterMarkerTests
{
    [Fact]
    public void TheMvcAdapterRegistration_LeavesItsMark()
    {
        var services = new ServiceCollection();
        services.AddOidcMvc();

        Assert.Contains(services, descriptor => descriptor.ServiceType == typeof(MvcAdapterMarker));
    }
}
