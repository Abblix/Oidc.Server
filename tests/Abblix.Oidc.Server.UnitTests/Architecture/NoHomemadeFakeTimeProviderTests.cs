// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// No assembly built here declares a FakeTimeProvider of its own.
/// </summary>
/// <remarks>
/// Microsoft.Extensions.Time.Testing ships one, and a second type under the same name answers a reader
/// who meets it with the wrong behavior: it advances, or fails to, by rules somebody wrote once for one
/// test. The walk covers only this repository's own assemblies, so the shipped one is never among them.
/// </remarks>
public class NoHomemadeFakeTimeProviderTests
{
    private const string Name = "FakeTimeProvider";

    [Fact]
    public void NoBuiltAssemblyDeclaresOne()
    {
        var assemblies = BuiltAssemblies.All;

        // The walk reached this very assembly, so an empty walk cannot pass as a clean tree.
        Assert.Contains(typeof(NoHomemadeFakeTimeProviderTests).Assembly.GetName().Name,
            assemblies.Select(assembly => assembly.GetName().Name));

        var homemade = assemblies
            .SelectMany(TypesOf)
            .Where(type => type.Name == Name || type.Name.StartsWith(Name + "`", StringComparison.Ordinal))
            .Select(type => $"{type.FullName} in {type.Assembly.GetName().Name}")
            .ToArray();

        Assert.True(homemade.Length == 0, string.Join(Environment.NewLine, homemade));
    }

    private static Type[] TypesOf(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException e)
        {
            return e.Types.Where(type => type is not null).ToArray()!;
        }
    }
}
