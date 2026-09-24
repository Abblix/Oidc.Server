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
using System.Reflection;
using System.Runtime.Loader;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Every assembly this repository builds, taken off disk rather than from what happens to be loaded.
/// </summary>
/// <remarks>
/// A test assembly other than this one is not a dependency of it, so nothing would load it and what it
/// declares would be invisible - which reads exactly like declaring nothing. Loaded once per run, because
/// each load hooks the resolver of the default context.
/// </remarks>
internal static class BuiltAssemblies
{
    private static readonly Lazy<IReadOnlyList<Assembly>> Loaded = new(Load);

    public static IReadOnlyList<Assembly> All => Loaded.Value;

    private static IReadOnlyList<Assembly> Load()
    {
        var root = RepositoryRoot();
        var byName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var neighbours = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Only what was built the way this test was. A tree keeps the output of every framework it has
        // ever targeted, and those older copies still hold the shapes of the day they were built - one of
        // them carries a Result that was a reference type, and loading it fails with a type mismatch that
        // names neither the staleness nor the folder. Taken from where this assembly is running rather
        // than written down, so it cannot drift from what it describes.
        var built = Path.Combine(
            Path.GetFileName(Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))!)!,
            Path.GetFileName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)));

        foreach (var area in new[] { "src", "tests" })
        {
            foreach (var path in Directory.EnumerateFiles(
                         Path.Combine(root, area), "*.dll", SearchOption.AllDirectories))
            {
                if (!path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}{built}{Path.DirectorySeparatorChar}"))
                    continue;

                var file = Path.GetFileName(path);

                // Everything found is offered to the loader, not only what this repository builds: reading
                // one assembly's members resolves the types they mention, and a package assembly that sits
                // beside only its own consumer is otherwise missing at exactly that moment.
                neighbours.TryAdd(file, path);

                // The first copy wins, and every copy is built from this same tree in the same run.
                if (file.StartsWith("Abblix.", StringComparison.Ordinal))
                    byName.TryAdd(file, path);
            }
        }

        AssemblyLoadContext.Default.Resolving += (context, name) =>
            name.Name is { } simple && neighbours.TryGetValue(simple + ".dll", out var found)
                ? context.LoadFromAssemblyPath(found)
                : null;

        var loaded = new List<Assembly>();
        foreach (var path in byName.Values)
        {
            try
            {
                // Loaded by path rather than by name: an assembly that is nobody's dependency is not
                // findable by name, and those are exactly the ones this walk exists to reach.
                loaded.Add(AssemblyLoadContext.Default.LoadFromAssemblyPath(path));
            }
            catch (Exception)
            {
                // A file that cannot be loaded is skipped, and every walk over this list is then blind
                // to it; only an assembly a caller names in its own floor is missed loudly.
            }
        }

        return loaded;
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
