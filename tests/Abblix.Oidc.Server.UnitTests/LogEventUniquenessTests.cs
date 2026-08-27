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
using Abblix.Oidc.Server;
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
    /// The count is asserted so the walk itself cannot quietly stop finding anything.
    /// </summary>
    /// <remarks>
    /// A uniqueness check over an empty set passes, and a walk that stops descending - a class nested one
    /// level deeper than it expected, a field kind it does not recognise - reports exactly that. The number
    /// is the instrument's own pulse rather than a fact about the product, so it is meant to be edited
    /// whenever an event is added; what it refuses is the edit nobody made.
    /// </remarks>
    [Fact]
    public void TheWalkFindsEveryDeclaredEvent()
    {
        Assert.Equal(151, EventIds().Count);
    }

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
