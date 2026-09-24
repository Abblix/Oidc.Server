// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
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
        var offences = ResultPairs(BuiltAssemblies.All)
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
    /// stopped matching finds no pairs.
    /// <para>
    /// What must be PRESENT rather than how many, because how many depends on what was built. A shard
    /// that builds this suite alone produces fewer assemblies than a whole-solution build, and a count
    /// taken from one of those layouts fails on the other while saying "wrong root" either way. The two
    /// named here are the one that declares the type and the one that carries most of its uses.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheWalkReachesTheAssembliesAndFindsPairs()
    {
        var assemblies = BuiltAssemblies.All;
        var names = assemblies.Select(assembly => assembly.GetName().Name).ToArray();

        Assert.Contains("Abblix.Utils", names);
        Assert.Contains("Abblix.Oidc.Server", names);

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
