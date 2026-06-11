// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Abblix.Oidc.Server.Mvc.SourceGeneration;

/// <summary>
/// The generation stub extracted from a hand-written partial record: where the model lives,
/// which core type it is generated from, and the type-level binding options. A pure value so
/// the incremental pipeline can cache on it.
/// </summary>
internal sealed record StubInfo(
	string Namespace,
	string Name,
	string CoreTypeName,
	bool SupportsGet,
	LocationInfo Location);

/// <summary>
/// The rendered output for one model: the hint name, the full source text (or null when generation
/// failed), and the diagnostics to report. A pure value so the driver skips re-emission when
/// nothing changed.
/// </summary>
internal sealed record GenerationResult(
	string HintName,
	string? Source,
	EquatableArray<DiagnosticInfo> Diagnostics);

/// <summary>
/// A diagnostic captured as equatable data; <see cref="Diagnostic"/> itself holds non-equatable
/// state and would defeat pipeline caching.
/// </summary>
internal sealed record DiagnosticInfo(DiagnosticDescriptor Descriptor, LocationInfo Location, params object?[] Arguments)
{
	public Diagnostic ToDiagnostic() => Diagnostic.Create(Descriptor, Location.ToLocation(), Arguments);

	public bool Equals(DiagnosticInfo? other)
		=> other != null &&
		   Descriptor.Id == other.Descriptor.Id &&
		   Location == other.Location &&
		   Arguments.SequenceEqual(other.Arguments);

	public override int GetHashCode()
	{
		var hashCode = Descriptor.Id.GetHashCode();
		hashCode = unchecked(hashCode * 31 + Location.GetHashCode());

		foreach (var argument in Arguments)
		{
			hashCode = unchecked(hashCode * 31 + (argument?.GetHashCode() ?? 0));
		}

		return hashCode;
	}
}

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
		=> Location.Create(
			FilePath,
			new TextSpan(SpanStart, SpanLength),
			new LinePositionSpan(
				new LinePosition(StartLine, StartCharacter),
				new LinePosition(EndLine, EndCharacter)));
}
