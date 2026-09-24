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
/// No assembly built here declares a clock of its own.
/// </summary>
/// <remarks>
/// Microsoft.Extensions.Time.Testing ships a FakeTimeProvider, and a hand-written TimeProvider answers a
/// reader who meets it with rules somebody wrote once for one test: it advances, or fails to, and its
/// timers fire, or do not, in ways nobody else's clock does. Found by what a type derives from rather than
/// by its name, so a copy under any name, generic or file-local, is found as well.
/// </remarks>
public class NoHomemadeClockTests
{
    [Fact]
    public void NoBuiltAssemblyDeclaresATimeProvider()
    {
        var assemblies = BuiltAssemblies.All;

        // The walk reached this very assembly, so an empty walk cannot pass as a clean tree.
        Assert.Contains(typeof(NoHomemadeClockTests).Assembly.GetName().Name,
            assemblies.Select(assembly => assembly.GetName().Name));

        var homemade = assemblies
            .SelectMany(TypesOf)
            .Where(type => type != typeof(TimeProvider) && typeof(TimeProvider).IsAssignableFrom(type))
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
