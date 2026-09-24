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
using System.Text.RegularExpressions;
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
            .Where(type => IsNamedFakeTimeProvider(type.Name))
            .Select(type => $"{type.FullName} in {type.Assembly.GetName().Name}")
            .ToArray();

        Assert.True(homemade.Length == 0, string.Join(Environment.NewLine, homemade));
    }

    /// <summary>
    /// Whether a metadata name is the one a type declared as FakeTimeProvider compiles to.
    /// </summary>
    /// <remarks>
    /// A generic type carries its arity after a backtick, and a file-local type is emitted under a name
    /// prefixed with its file and a hash, so neither ever equals the plain name.
    /// </remarks>
    private static bool IsNamedFakeTimeProvider(string metadataName)
        => Regex.IsMatch(metadataName, $"^(<[^>]*>F[0-9A-F]+__)?{Name}(`[0-9]+)?$");

    [Theory]
    [InlineData("FakeTimeProvider", true)]
    [InlineData("FakeTimeProvider`1", true)]
    [InlineData("<Plant>F715B6F1C7E68__FakeTimeProvider", true)]
    [InlineData("<Plant>F715B6F1C7E68__FakeTimeProvider`2", true)]
    [InlineData("FakeTimeProviderTests", false)]
    [InlineData("MyFakeTimeProvider", false)]
    public void EveryShapeTheCompilerGivesTheNameIsRecognized(string metadataName, bool expected)
        => Assert.Equal(expected, IsNamedFakeTimeProvider(metadataName));

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
