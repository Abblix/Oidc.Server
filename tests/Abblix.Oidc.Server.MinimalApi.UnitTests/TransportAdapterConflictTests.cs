// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Reflection;
using System.Reflection.Emit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// The startup refusal that fires when an application carries both OIDC transport adapters.
/// </summary>
/// <remarks>
/// Observed live: a host that swapped the MVC adapter for this one but left the MVC package referenced saw all
/// 460 of its conformance tests fail, every one of them at the first request with an AmbiguousMatchException
/// naming the routing layer. Nothing in that message points at the two packages, which is what this guard is
/// for. The decision is exercised over a supplied assembly list rather than the ambient AppDomain, because
/// loading the other adapter into this process is irreversible and would then trip every test that maps
/// endpoints.
/// </remarks>
public class TransportAdapterConflictTests
{
    private static Assembly Named(string name)
        => AssemblyBuilder.DefineDynamicAssembly(new AssemblyName(name), AssemblyBuilderAccess.Run);

    /// <summary>
    /// Nothing but the MVC adapter may trip the guard. A name that merely starts or ends the same way belongs
    /// to a different assembly, and refusing over one would be the worse failure: a host that has done nothing
    /// wrong, told to remove a package it does not reference.
    /// </summary>
    [Theory]
    [InlineData("Abblix.Oidc.Server")]
    [InlineData("Abblix.Oidc.Server.MinimalApi")]
    [InlineData("Abblix.Oidc.Server.MvcSomethingElse")]
    [InlineData("Contoso.Abblix.Oidc.Server.Mvc")]
    public void A_host_without_the_MVC_adapter_is_left_alone(string assemblyName)
    {
        var exception = Record.Exception(
            () => TransportAdapterConflict.ThrowIfAdaptersPresent(
                [Named("SomeHost"), Named(assemblyName)]));

        Assert.Null(exception);
    }

    /// <summary>
    /// The message has one job: say which package to remove. A guard that only reports a conflict leaves the
    /// reader where the routing error already left them.
    /// </summary>
    [Fact]
    public void The_refusal_names_both_packages_and_the_call_to_drop()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => TransportAdapterConflict.ThrowIfAdaptersPresent(
                [Named("SomeHost"), Named("Abblix.Oidc.Server.Mvc")]));

        Assert.Contains("Abblix.OIDC.Server.MVC", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Abblix.OIDC.Server.MinimalApi", exception.Message, StringComparison.Ordinal);
        Assert.Contains("MapOidcEndpoints()", exception.Message, StringComparison.Ordinal);
        Assert.Contains("AmbiguousMatchException", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A host carrying only this adapter starts, which is the case that must never be refused.
    /// </summary>
    [Fact]
    public void A_host_carrying_only_this_adapter_is_allowed_to_start()
    {
        var exception = Record.Exception(
            () => TransportAdapterConflict.ThrowIfAdaptersPresent(
                [Named("SomeHost"), Named("Abblix.Oidc.Server.MinimalApi")]));

        Assert.Null(exception);
    }
}
