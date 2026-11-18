// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The algorithms the library registers by default, read from the same registrations a host gets.
/// </summary>
internal static class RegisteredAlgorithms
{
    /// <summary>The default signature algorithms.</summary>
    public static SigningAlgorithmsProvider Signing { get; } = new ServiceCollection()
        .AddSingleton(TimeProvider.System)
        .AddLogging()
        .AddJsonWebTokens()
        .BuildServiceProvider()
        .GetRequiredService<SigningAlgorithmsProvider>();
}
