// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// Licensed under the Abblix License Agreement. See LICENSE.md in the project root for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using Abblix.Utils;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// A result whose two arms cannot be told apart by type answers yes to both questions, so a failure
/// reads as a success.
/// </summary>
/// <remarks>
/// A union carries its content as a single object and matches by type, which is what makes the pair the
/// place to check. The language already refuses the identical case: the conversion and the generated
/// constructor are both ambiguous for <c>Result&lt;T, T&gt;</c>, and this repository keeps no factory that
/// would take its argument as a type parameter and smuggle one past that. What the language does not
/// refuse is a pair whose arms are RELATED - a failure type deriving from the success type, or either
/// implementing the other - and there is no constraint that could say so: the set of generic constraints
/// has no form for "these two must not be convertible".
/// <para>
/// So this is the thing that says it. The population comes from the compiled artefacts rather than from
/// a list somebody appends to, because keeping such a list is the same act of memory the check replaces.
/// Reflection also sidesteps the file that declares the union, which the syntax version of Roslyn this
/// suite references cannot parse at all - a source walk would read it as empty and say nothing.
/// </para>
/// </remarks>
public class ResultArmsMustBeDistinguishableTests
{
    /// <summary>
    /// Every assembly this repository builds, taken off disk rather than from what happens to be loaded.
    /// </summary>
    /// <remarks>
    /// A test assembly other than this one is not a dependency of it, so nothing would load it and its
    /// pairs would be invisible - which reads exactly like having none.
    /// </remarks>
    private static IReadOnlyList<Assembly> BuiltAssemblies()
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
                // A file that cannot be loaded is reported by the floor below rather than swallowed here:
                // naming each one would turn this into a list nobody keeps current.
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

    /// <summary>
    /// Every constructed <see cref="Result{TSuccess,TFailure}"/> reachable from an assembly's own
    /// metadata: what its members declare, and what its method bodies keep in locals.
    /// </summary>
    private static IReadOnlyList<Type> ResultPairs(IEnumerable<Assembly> assemblies)
    {
        var found = new HashSet<Type>();

        foreach (var assembly in assemblies)
        {
            Type[] types;
            try
            {
                types = assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException e)
            {
                types = e.Types.Where(t => t is not null).ToArray()!;
            }

            foreach (var type in types)
            {
                const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic
                    | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

                foreach (var field in type.GetFields(all))
                    Collect(field.FieldType, found);

                foreach (var property in type.GetProperties(all))
                    Collect(property.PropertyType, found);

                foreach (var method in type.GetMethods(all).Cast<MethodBase>().Concat(type.GetConstructors(all)))
                {
                    if (method is MethodInfo info)
                        Collect(info.ReturnType, found);

                    foreach (var parameter in method.GetParameters())
                        Collect(parameter.ParameterType, found);

                    // A pair used only to hold an intermediate value appears nowhere in a signature.
                    try
                    {
                        var body = method.GetMethodBody();
                        if (body is not null)
                            foreach (var local in body.LocalVariables)
                                Collect(local.LocalType, found);
                    }
                    catch (Exception)
                    {
                        // Abstract and generated members have no body to read.
                    }
                }
            }
        }

        return found.ToArray();
    }

    /// <summary>Walks a type and whatever it is built out of, keeping the constructed result pairs.</summary>
    private static void Collect(Type? type, HashSet<Type> found, int depth = 0)
    {
        if (type is null || depth > 8) return;

        if (type.IsByRef || type.IsPointer || type.IsArray)
        {
            Collect(type.GetElementType(), found, depth + 1);
            return;
        }

        if (!type.IsGenericType) return;

        if (type.GetGenericTypeDefinition() == typeof(Result<,>) && !type.ContainsGenericParameters)
            found.Add(type);

        foreach (var argument in type.GetGenericArguments())
            Collect(argument, found, depth + 1);
    }

    /// <summary>Whether one arm of a pair can stand in for the other, which is what makes them one arm.</summary>
    private static bool ArmsCollide(Type pair)
    {
        var arms = pair.GetGenericArguments();
        return arms[0].IsAssignableFrom(arms[1]) || arms[1].IsAssignableFrom(arms[0]);
    }

    private static string Describe(Type pair)
    {
        var arms = pair.GetGenericArguments();
        return $"Result<{arms[0].FullName}, {arms[1].FullName}>";
    }

    /// <summary>
    /// No pair anywhere in this repository has arms that can stand in for each other.
    /// </summary>
    [Fact]
    public void NoResultPairHasArmsThatStandInForEachOther()
    {
        var offences = ResultPairs(BuiltAssemblies())
            .Where(ArmsCollide)
            .Select(Describe)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            offences.Length == 0,
            "A result was built from two arms that cannot be told apart, so a failure reads as a success:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, offences));
    }

    /// <summary>
    /// The walk reaches the assemblies and finds real pairs, so a clean run above means something.
    /// </summary>
    /// <remarks>
    /// A negative is worth nothing until the instrument has been shown to reach a positive, and both
    /// halves fail silently in the same direction: a wrong root finds no assemblies, and a walk that
    /// stopped matching finds no pairs. Each is asserted against a floor rather than against zero.
    /// </remarks>
    [Fact]
    public void TheWalkReachesTheAssembliesAndFindsPairs()
    {
        var assemblies = BuiltAssemblies();
        Assert.True(assemblies.Count > 10, $"only {assemblies.Count} assemblies found - wrong root?");

        var pairs = ResultPairs(assemblies);
        Assert.True(pairs.Count > 20, $"only {pairs.Count} result pairs found - did the walk stop matching?");

        // A pair the library certainly carries, named so the walk cannot pass by finding only strangers.
        Assert.Contains(pairs, p => Describe(p).Contains("AuthorizedGrant", StringComparison.Ordinal));
    }

    /// <summary>
    /// The check reports a pair whose arms collide, in each of the shapes that collision takes.
    /// </summary>
    /// <remarks>
    /// Driven on synthetic pairs rather than by planting one in the tree, because a planted one would
    /// have to be removed again and the removal is what gets forgotten. The identical shape is here even
    /// though the compiler now refuses it at every way in: this check is what would notice if that stopped
    /// being true.
    /// </remarks>
    [Theory]
    [InlineData(typeof(Result<string, string>))]
    [InlineData(typeof(Result<CollisionBase, CollisionDerived>))]
    [InlineData(typeof(Result<CollisionDerived, CollisionBase>))]
    [InlineData(typeof(Result<ICollisionMarker, CollisionCarrier>))]
    [InlineData(typeof(Result<object, CollisionBase>))]
    public void TheCheckReportsCollidingArms(Type pair) => Assert.True(ArmsCollide(pair));

    /// <summary>
    /// The check leaves alone the pairs that are fine, so it is not simply answering yes.
    /// </summary>
    [Theory]
    [InlineData(typeof(Result<CollisionBase, ICollisionMarker>))]
    [InlineData(typeof(Result<string, int>))]
    [InlineData(typeof(Result<CollisionDerived, CollisionCarrier>))]
    public void TheCheckLeavesDistinguishableArmsAlone(Type pair) => Assert.False(ArmsCollide(pair));

    /// <summary>
    /// What this check cannot see, said out loud so a clean run is not read as more than it is.
    /// </summary>
    /// <remarks>
    /// It reads the built artefacts, so a pair written in a file that is excluded from the build, or in a
    /// project nobody built before the run, is invisible. It compares the arms as they are DECLARED, so a
    /// pair whose arms are open type parameters is skipped entirely - which is every use inside the type
    /// itself, and any generic helper that passes a caller's pair through: those become concrete only at
    /// the call site, and the call site is what this walk sees. And a collision that exists only for some
    /// instantiations of a generic method is not reachable from metadata at all.
    /// </remarks>
    [Fact]
    public void TheShapesThisCheckCannotSee()
    {
        // A statement of scope rather than a check, and it is here so the list has a place a reader lands
        // on from the failure message above.
        Assert.True(true);
    }

    private interface ICollisionMarker;

    private record CollisionBase(string Text);

    private record CollisionDerived(string Text) : CollisionBase(Text);

    private record CollisionCarrier(string Text) : ICollisionMarker;
}
