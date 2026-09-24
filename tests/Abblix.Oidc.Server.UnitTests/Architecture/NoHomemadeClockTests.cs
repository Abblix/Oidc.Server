// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml.Linq;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// No assembly built here declares a clock of its own.
/// </summary>
/// <remarks>
/// Microsoft.Extensions.Time.Testing ships a FakeTimeProvider, and a hand-written TimeProvider answers a
/// reader who meets it with rules somebody wrote once for one test: it advances, or fails to, and its
/// timers fire, or do not, in ways nobody else's clock does. Found by what a type derives from rather than
/// by its name, so a copy under any name, generic or file-local, is found as well. A mocking library's
/// proxy is created while the tests run, in an assembly no build writes, and is not seen here.
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
            .Where(IsAClock)
            .Select(type => $"{type.FullName} in {type.Assembly.GetName().Name}")
            .ToArray();

        Assert.True(homemade.Length == 0, string.Join(Environment.NewLine, homemade));
    }

    /// <summary>
    /// Every project of the solution is built before this one, so the walk above reads all of them from
    /// their current sources.
    /// </summary>
    /// <remarks>
    /// Continuous integration builds and runs each test project on its own, and the walk can only read what
    /// that build produced. A project this one does not reach through its references would be read from an
    /// earlier build on a developer's machine, and not at all in continuous integration.
    /// </remarks>
    [Fact]
    public void EveryProjectOfTheSolutionIsBuiltBeforeThisOne()
    {
        var root = RepositoryRoot();
        var self = Path.Combine(root, "tests", "Abblix.Oidc.Server.UnitTests", "Abblix.Oidc.Server.UnitTests.csproj");

        var solution = XDocument.Load(Path.Combine(root, "Abblix.Oidc.slnx"))
            .Descendants("Project")
            .Select(project => Path.GetFullPath(Path.Combine(root, (string)project.Attribute("Path")!)))
            .ToHashSet(StringComparer.Ordinal);

        var reached = ReachedFrom(self);

        var unreached = solution
            .Where(project => !string.Equals(project, self, StringComparison.Ordinal) && !reached.Contains(project))
            .Select(project => Path.GetRelativePath(root, project))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(unreached.Length == 0,
            $"in Abblix.Oidc.slnx but not reached through this project's references: {string.Join(", ", unreached)}");
    }

    /// <summary>The check itself: it answers yes for a clock and no for anything else.</summary>
    [Theory]
    [InlineData(typeof(FakeTimeProvider), true)]
    [InlineData(typeof(TimeProvider), false)]
    [InlineData(typeof(NoHomemadeClockTests), false)]
    public void TheCheckRecognizesAClock(Type type, bool expected)
        => Assert.Equal(expected, IsAClock(type));

    private static bool IsAClock(Type type)
        => type != typeof(TimeProvider) && typeof(TimeProvider).IsAssignableFrom(type);

    /// <summary>Every project a project file reaches through its references, directly or through another.</summary>
    private static HashSet<string> ReachedFrom(string projectFile)
    {
        var reached = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>([projectFile]);

        while (pending.TryPop(out var current))
        {
            var directory = Path.GetDirectoryName(current)!;
            foreach (var reference in XDocument.Load(current).Descendants("ProjectReference"))
            {
                var path = Path.GetFullPath(Path.Combine(directory,
                    ((string)reference.Attribute("Include")!).Replace('\\', Path.DirectorySeparatorChar)));

                if (reached.Add(path))
                    pending.Push(path);
            }
        }

        return reached;
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
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
