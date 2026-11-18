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

public static class TestSigningAlgorithms
{
    /// <summary>The signature algorithms the library registers by default.</summary>
    public static SigningAlgorithmsProvider Registered { get; } = Build();

    private static SigningAlgorithmsProvider Build()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider().GetRequiredService<SigningAlgorithmsProvider>();
    }
}
