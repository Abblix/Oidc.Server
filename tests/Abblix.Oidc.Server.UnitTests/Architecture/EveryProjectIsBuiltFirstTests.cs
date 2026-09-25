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

        var reached = ReachedFrom(self, root);

        var unreached = solution
            .Where(project => !string.Equals(project, self, StringComparison.Ordinal) && !reached.Contains(project))
            .Select(project => Path.GetRelativePath(root, project))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(unreached.Length == 0,
            $"in Abblix.Oidc.slnx but not reached through this project's references: {string.Join(", ", unreached)}");
    }

    /// <summary>
    /// Every project a project file reaches through its references, directly or through another, and
    /// through the ones the repository-wide Directory.Build.props gives every project.
    /// </summary>
    private static HashSet<string> ReachedFrom(string projectFile, string root)
    {
        var reached = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>([projectFile]);

        foreach (var shared in ReferencesIn(Path.Combine(root, "Directory.Build.props"), root))
        {
            if (reached.Add(shared))
                pending.Push(shared);
        }

        while (pending.TryPop(out var current))
        {
            foreach (var path in ReferencesIn(current, Path.GetDirectoryName(current)!))
            {
                if (reached.Add(path))
                    pending.Push(path);
            }
        }

        return reached;
    }

    private static IEnumerable<string> ReferencesIn(string file, string directory)
        => XDocument.Load(file)
            .Descendants("ProjectReference")
            .Select(reference => (string?)reference.Attribute("Include"))
            .OfType<string>()
            .Select(include => Path.GetFullPath(Path.Combine(directory,
                include.Replace("$(MSBuildThisFileDirectory)", string.Empty, StringComparison.Ordinal)
                    .Replace('\\', Path.DirectorySeparatorChar))));

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }
}
