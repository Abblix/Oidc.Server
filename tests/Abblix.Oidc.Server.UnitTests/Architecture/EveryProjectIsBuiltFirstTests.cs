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
using System.Text.Json;
using System.Xml.Linq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// Every project of the solution is built before this one, so the walks over <c>BuiltAssemblies</c>
/// read all of them from their current sources.
/// </summary>
/// <remarks>
/// Continuous integration builds and runs each test project on its own, and a walk can only read what
/// that build produced. A project this one does not reach through its references would be read from an
/// earlier build on a developer's machine, and not at all in continuous integration.
/// The references are the ones the build itself resolved rather than a reading of project files: the
/// direct ones as MSBuild evaluated them for this project, conditions applied, and the ones reached
/// through them as NuGet's restore recorded them.
/// </remarks>
public class EveryProjectIsBuiltFirstTests
{
    [Fact]
    public void EveryProjectOfTheSolutionIsBuiltBeforeThisOne()
    {
        var root = RepositoryRoot();
        var self = Path.Combine(root, "tests", "Abblix.Oidc.Server.UnitTests", "Abblix.Oidc.Server.UnitTests.csproj");

        var solution = XDocument.Load(Path.Combine(root, "Abblix.Oidc.slnx"))
            .Descendants("Project")
            .Select(project => Path.GetFullPath(Path.Combine(root, (string)project.Attribute("Path")!)))
            .ToHashSet(StringComparer.Ordinal);

        var direct = DirectReferences();

        // The control: an attribute written from an item group placed above the references, or under a
        // renamed key, carries nothing, and every project would then read as unreached for the wrong
        // reason - or, were the check inverted, as reached.
        Assert.Contains(Path.Combine(root, "src", "Abblix.Analyzers", "Abblix.Analyzers.csproj"), direct);

        var reached = direct.Concat(RestoredReferences(self)).ToHashSet(StringComparer.Ordinal);

        var unreached = solution
            .Where(project => !string.Equals(project, self, StringComparison.Ordinal) && !reached.Contains(project))
            .Select(project => Path.GetRelativePath(root, project))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(unreached.Length == 0,
            $"in Abblix.Oidc.slnx but not reached through this project's references: {string.Join(", ", unreached)}");
    }

    /// <summary>The project references MSBuild evaluated for this project, written into the assembly.</summary>
    private static string[] DirectReferences()
        => typeof(EveryProjectIsBuiltFirstTests).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(attribute => attribute.Key == "ProjectReferences")
            .Value!
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(Path.GetFullPath)
            .ToArray();

    /// <summary>
    /// The projects NuGet's restore resolved for this project, directly or through another one.
    /// </summary>
    private static IEnumerable<string> RestoredReferences(string projectFile)
    {
        var directory = Path.GetDirectoryName(projectFile)!;
        using var assets = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "obj", "project.assets.json")));

        return assets.RootElement.GetProperty("libraries").EnumerateObject()
            .Where(library => library.Value.GetProperty("type").GetString() == "project")
            .Select(library => Path.GetFullPath(Path.Combine(directory, library.Value.GetProperty("path").GetString()!)))
            .ToArray();
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }
}
