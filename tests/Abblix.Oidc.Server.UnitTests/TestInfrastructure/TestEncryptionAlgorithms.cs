// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// The registry of key management algorithms a host builds with <c>AddJsonWebTokens</c>, which the server asks which key
/// types an algorithm is carried out with.
/// </summary>
public static class TestEncryptionAlgorithms
{
    /// <summary>
    /// Every key management algorithm the library carries, those a host opts into (RSA1_5, PBES2) included: what a
    /// test serves is narrowed by the algorithms its own token creator advertises.
    /// </summary>
    public static EncryptionAlgorithmsProvider Every { get; } = With(services => services
        .AddRsaPkcs1KeyManagement()
        .AddPbes2KeyManagement());

    /// <summary>The built-in key management algorithms and whatever <paramref name="register"/> adds.</summary>
    /// <param name="register">Registers the host's own algorithms.</param>
    public static EncryptionAlgorithmsProvider With(Action<IServiceCollection> register)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        register(services);
        return services.BuildServiceProvider().GetRequiredService<EncryptionAlgorithmsProvider>();
    }
}
