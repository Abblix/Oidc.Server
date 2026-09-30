// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Oidc.Server.Features.Licensing;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// The license this process runs under: the multi-tenant test license, which names the issuers of both tenants
/// the suites here serve.
/// </summary>
internal static class TestLicense
{
    public static readonly Task Loaded = LoadAsync();

    private static async Task LoadAsync()
    {
        var assembly = Assembly.GetExecutingAssembly();
        const string name = "Abblix.Oidc.Server.MultiTenancy.E2E.Tests.Resources.test-license-multitenant.jwt";
        await using var stream = assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"The embedded license {name} is missing.");
        using var reader = new StreamReader(stream);
        await LicenseLoader.LoadAsync((await reader.ReadToEndAsync()).Trim());
    }
}
