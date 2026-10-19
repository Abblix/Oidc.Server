// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using System.Linq;
using System.Reflection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// Every log event id of every package of the library belongs to one event.
/// </summary>
/// <remarks>
/// Nothing else checks this. The compiler does not, because two classes may hold equal constants; the
/// LoggerMessage generator does not, because it looks at one declaration at a time; and the build reports
/// no warning. What ships is one number carrying two meanings - a warning about a refused authorization
/// and a debug line about an outbound request, say - which defeats the only reason the files maintain
/// documented ranges at all: an operator alerting on an id gets both.
///
/// The packages run in one process - a server with a key custodian and a Shared Signals transmitter loads
/// most of them - so a number is unique only if it is unique across all of them, and each package keeps its
/// own <c>LogEvents</c> class where a neighbour's numbers are out of sight. So the walk covers every
/// <c>LogEvents</c> class of every library assembly the tests load.
///
/// Read by reflection rather than by parsing the files, so a declaration written in any shape - Base plus
/// an offset, a bare literal, a new nesting depth - is counted. The private Base constants are excluded by
/// asking for public fields only, which is what makes them safe to reuse across classes.
/// </remarks>
public class LogEventUniquenessTests
{
    [Fact]
    public void EveryLogEventIdIsDeclaredOnce()
    {
        var duplicates = EventIds()
            .GroupBy(entry => entry.Id)
            .Where(group => group.Count() > 1)
            .Select(group => $"{group.Key}: {string.Join(", ", group.Select(entry => entry.Name))}")
            .ToArray();

        Assert.Empty(duplicates);
    }

    /// <summary>
    /// The walk reaches the events of every package that logs, at both ends of the server's declarations, and
    /// finds more than a handful, so the uniqueness check above runs over the real set rather than over whatever
    /// a broken walk leaves.
    /// </summary>
    /// <remarks>
    /// A uniqueness check over an empty set passes, and so does one over a set a walk stopped short of. The
    /// packages and the first and the last event declared are named rather than counted: a count has to be
    /// edited with every event added, and an edit made to turn a test green is made without looking at why it
    /// was red.
    /// </remarks>
    [Fact]
    public void TheWalkReachesTheDeclaredEvents()
    {
        var found = EventIds();

        Assert.Contains(found, entry => entry.Id == LogEvents.Endpoints.JwtBearer.MissingAssertion);
        Assert.Contains(found, entry => entry.Id == LogEvents.RateLimiting.UnnamedSourceNotice.BudgetLeavesUncharged);
        Assert.True(found.Count > MinimumDeclaredEvents, $"The walk found only {found.Count} events");

        string[] packagesThatLog =
        [
            "Abblix.Jwt",
            "Abblix.Jwt.Azure",
            "Abblix.Jwt.Vault",
            "Abblix.Oidc.Server",
            "Abblix.Oidc.Server.AspNetCore",
            "Abblix.Oidc.Server.SharedSignals",
            "Abblix.SecurityEvents",
            "Abblix.SharedSignals",
        ];
        var walked = found.Select(entry => entry.Package).ToHashSet(StringComparer.Ordinal);
        Assert.All(packagesThatLog, package => Assert.Contains(package, walked));
    }

    /// <summary>
    /// Far below the events declared, and far above what a walk that stopped at the first group finds.
    /// </summary>
    private const int MinimumDeclaredEvents = 100;

    private static IReadOnlyList<(int Id, string Name, string Package)> EventIds()
    {
        var found = new List<(int, string, string)>();
        foreach (var assembly in LibraryAssemblies())
        {
            var package = assembly.GetName().Name!;
            foreach (var type in assembly.GetTypes().Where(type => type is { Name: "LogEvents", DeclaringType: null }))
                Collect(type, package, $"{package}: ", found);
        }

        return found;
    }

    /// <summary>
    /// The library's assemblies, the test assemblies and the hosts they start excluded: a test may declare
    /// event ids of its own, and nothing a test logs reaches a deployment.
    /// </summary>
    private static IEnumerable<Assembly> LibraryAssemblies()
        =>
            from assembly in BuiltAssemblies.All
            let name = assembly.GetName().Name!
            where !name.Contains("Test", StringComparison.Ordinal) &&
                  !name.Contains("DocSamples", StringComparison.Ordinal)
            select assembly;

    private static void Collect(Type type, string package, string prefix, List<(int, string, string)> found)
    {
        const BindingFlags Declared = BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly;

        foreach (var field in type.GetFields(Declared))
        {
            if (field is { IsLiteral: true, IsInitOnly: false } && field.FieldType == typeof(int))
                found.Add(((int)field.GetRawConstantValue()!, prefix + field.Name, package));
        }

        foreach (var nested in type.GetNestedTypes(BindingFlags.Public | BindingFlags.NonPublic))
        {
            Collect(nested, package, $"{prefix}{nested.Name}.", found);
        }
    }
}
