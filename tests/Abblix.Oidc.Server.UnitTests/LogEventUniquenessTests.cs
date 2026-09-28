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
using Xunit;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// Every log event id belongs to one event.
/// </summary>
/// <remarks>
/// Nothing else checks this. The compiler does not, because two classes may hold equal constants; the
/// LoggerMessage generator does not, because it looks at one declaration at a time; and the build reports
/// no warning. What ships is one number carrying two meanings - a warning about a refused authorization
/// and a debug line about an outbound request, say - which defeats the only reason the file maintains
/// documented sub-ranges at all: an operator alerting on an id gets both.
///
/// The failure is easy to walk into. The ranges are prose, so picking the next free number means reading
/// every declaration rather than the nearest one, and the nearest one is what a reader reaches for. It has
/// happened twice.
///
/// Read by reflection rather than by parsing the file, so a declaration written in any shape - Base plus
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
    /// The walk reaches the events at both ends of the declarations and finds more than a handful, so the
    /// uniqueness check above runs over the real set rather than over whatever a broken walk leaves.
    /// </summary>
    /// <remarks>
    /// A uniqueness check over an empty set passes, and so does one over a set a walk stopped short of. The
    /// first and the last event declared are named rather than counted: a count has to be edited with every
    /// event added, and an edit made to turn a test green is made without looking at why it was red.
    /// </remarks>
    [Fact]
    public void TheWalkReachesTheDeclaredEvents()
    {
        var found = EventIds();

        Assert.Contains(found, entry => entry.Id == LogEvents.Endpoints.JwtBearer.MissingAssertion);
        Assert.Contains(found, entry => entry.Id == LogEvents.RateLimiting.UnnamedSourceNotice.BudgetLeavesUncharged);
        Assert.True(found.Count > MinimumDeclaredEvents, $"The walk found only {found.Count} events");
    }

    /// <summary>
    /// Far below the events declared, and far above what a walk that stopped at the first group finds.
    /// </summary>
    private const int MinimumDeclaredEvents = 100;

    private static IReadOnlyList<(int Id, string Name)> EventIds()
    {
        var found = new List<(int, string)>();
        Collect(typeof(LogEvents), string.Empty, found);
        return found;
    }

    private static void Collect(Type type, string prefix, List<(int, string)> found)
    {
        const BindingFlags Declared = BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly;

        foreach (var field in type.GetFields(Declared))
        {
            if (field is { IsLiteral: true, IsInitOnly: false } && field.FieldType == typeof(int))
                found.Add(((int)field.GetRawConstantValue()!, prefix + field.Name));
        }

        foreach (var nested in type.GetNestedTypes(BindingFlags.Public))
        {
            Collect(nested, $"{prefix}{nested.Name}.", found);
        }
    }
}
