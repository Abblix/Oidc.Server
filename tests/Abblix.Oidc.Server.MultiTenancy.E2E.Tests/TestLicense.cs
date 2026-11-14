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
    /// <summary>
    /// The license as a host supplies it; read before the loading below, which static initialization runs in order.
    /// </summary>
    public static string Jwt { get; } = Read();

    public static readonly Task Loaded = LoadAsync();

    private static async Task LoadAsync() => await LicenseLoader.LoadAsync(Jwt);

    private static string Read()
    {
        var assembly = Assembly.GetExecutingAssembly();
        const string name = "Abblix.Oidc.Server.MultiTenancy.E2E.Tests.Resources.test-license-multitenant.jwt";
        using var stream = assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"The embedded license {name} is missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim();
    }
}
