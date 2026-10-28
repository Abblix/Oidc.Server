// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// The shared host is handed to test classes that run in parallel, so it has to serve concurrent callers and
/// still be released when the run ends.
/// </summary>
public sealed class TestFactoryTests
{
    /// <summary>
    /// Fresh factories, so the records of what each one handed out start empty and grow under contention again.
    /// </summary>
    private const int Factories = 8;

    /// <summary>
    /// Enough concurrent calls per factory that its records grow many times while the callers race.
    /// </summary>
    private const int Calls = 4_000;

    [Fact]
    public Task ClientsHandedOutConcurrently_AreReleasedWithTheFactory()
        => HandOutConcurrentlyAndRelease(factory => factory.CreateClient(new WebApplicationFactoryClientOptions()));

    [Fact]
    public Task VariantsHandedOutConcurrently_AreReleasedWithTheFactory()
        => HandOutConcurrentlyAndRelease(factory => factory.WithWebHostBuilder(_ => { }));

    private static async Task HandOutConcurrentlyAndRelease(Action<TestFactory> handOut)
    {
        for (var round = 0; round < Factories; round++)
        {
            var factory = new TestFactory();
            await factory.InitializeAsync();

            Parallel.For(0, Calls, _ => handOut(factory));

            Assert.Null(await Record.ExceptionAsync(() => factory.DisposeAsync().AsTask()));
        }
    }
}
