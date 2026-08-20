// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using System.Reflection.Emit;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests;

/// <summary>
/// The startup refusal that fires when an application carries both OIDC transport adapters.
/// </summary>
/// <remarks>
/// Observed live: a host that swapped the MVC adapter for the Minimal API one but left the MVC package
/// referenced saw all 460 of its conformance tests fail, every one of them at the first request with an
/// AmbiguousMatchException naming the routing layer. Nothing in that message points at the two packages, which
/// is what this guard is for. The assembly decision runs over a supplied list rather than the ambient
/// AppDomain, because loading the other adapter into this process is irreversible and would then trip every
/// test that maps endpoints.
/// </remarks>
public class TransportAdapterConflictTests
{
    private const string Message = "remove one of the two packages";

    private static Assembly Named(string name)
        => AssemblyBuilder.DefineDynamicAssembly(new AssemblyName(name), AssemblyBuilderAccess.Run);

    [Fact]
    public void An_application_that_loaded_the_other_adapter_is_refused()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => TransportAdapterConflict.ThrowIfLoaded(
                TransportAdapterConflict.MvcAdapterAssemblyName,
                Message,
                [Named("SomeHost"), Named(TransportAdapterConflict.MvcAdapterAssemblyName)]));

        Assert.Equal(Message, exception.Message);
    }

    /// <summary>
    /// Nothing but the named adapter may trip the guard. A name that merely starts or ends the same way
    /// belongs to a different assembly, and refusing over one would be the worse failure: a host that has done
    /// nothing wrong, told to remove a package it does not reference.
    /// </summary>
    [Theory]
    [InlineData("Abblix.Oidc.Server")]
    [InlineData("Abblix.Oidc.Server.MinimalApi")]
    [InlineData("Abblix.Oidc.Server.MvcSomethingElse")]
    [InlineData("Contoso.Abblix.Oidc.Server.Mvc")]
    public void An_application_without_the_other_adapter_starts(string assemblyName)
    {
        var exception = Record.Exception(
            () => TransportAdapterConflict.ThrowIfLoaded(
                TransportAdapterConflict.MvcAdapterAssemblyName,
                Message,
                [Named("SomeHost"), Named(assemblyName)]));

        Assert.Null(exception);
    }

    /// <summary>
    /// The registration signal, which is what each adapter checks when the other one's registration ran first.
    /// A contract declared in this test assembly stands in for one an adapter would register, and the guard is
    /// pointed at this assembly's name.
    /// </summary>
    [Fact]
    public void An_application_that_registered_the_other_adapter_is_refused()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAdapterContract, AdapterContract>();

        var exception = Assert.Throws<InvalidOperationException>(
            () => TransportAdapterConflict.ThrowIfRegistered(services, ThisAssemblyName, Message));

        Assert.Equal(Message, exception.Message);
    }

    /// <summary>
    /// A collection holding nothing from the other adapter is left alone - the case that must never be
    /// refused, since it is what every single-adapter host looks like.
    /// </summary>
    [Fact]
    public void An_application_without_the_other_adapter_registered_starts()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAdapterContract, AdapterContract>();

        var exception = Record.Exception(
            () => TransportAdapterConflict.ThrowIfRegistered(services, "Some.Other.Adapter", Message));

        Assert.Null(exception);
    }

    private static string ThisAssemblyName => typeof(IAdapterContract).Assembly.GetName().Name!;

    /// <summary>A stand-in for a contract one of the adapters would register.</summary>
    private interface IAdapterContract;

    private sealed class AdapterContract : IAdapterContract;
}
