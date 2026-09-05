// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Abblix.Oidc.Server.SourceGenerators;

/// <summary>
/// A source location captured as equatable primitives, restorable to a <see cref="Location"/>
/// when the diagnostic is finally reported.
/// </summary>
internal sealed record LocationInfo(
    string FilePath,
    int SpanStart,
    int SpanLength,
    int StartLine,
    int StartCharacter,
    int EndLine,
    int EndCharacter)
{
    /// <summary>A placeholder for a diagnostic that is not tied to a source span (an assembly-wide condition).</summary>
    public static readonly LocationInfo None = new(string.Empty, 0, 0, 0, 0, 0, 0);

    public static LocationInfo From(Location location)
    {
        var lineSpan = location.GetLineSpan();
        return new LocationInfo(
            lineSpan.Path,
            location.SourceSpan.Start,
            location.SourceSpan.Length,
            lineSpan.StartLinePosition.Line,
            lineSpan.StartLinePosition.Character,
            lineSpan.EndLinePosition.Line,
            lineSpan.EndLinePosition.Character);
    }

    public Location ToLocation()
        => string.IsNullOrEmpty(FilePath)
            ? Location.None
            : Location.Create(
                FilePath,
                new TextSpan(SpanStart, SpanLength),
                new LinePositionSpan(
                    new LinePosition(StartLine, StartCharacter),
                    new LinePosition(EndLine, EndCharacter)));
}