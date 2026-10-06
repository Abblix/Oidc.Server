// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.CodeAnalysis;

namespace Abblix.Oidc.Server.SourceGenerators.Telemetry;

/// <summary>
/// One entry of the list, read off its attribute, while its decorator is checked and written. It holds symbols, so it
/// lives within one transform and never reaches the pipeline's cache.
/// </summary>
/// <param name="Service">The handler interface the decorator implements.</param>
/// <param name="ClassName">The name of the decorator.</param>
/// <param name="Kind">What the decorator observes.</param>
/// <param name="Name">The endpoint the handler serves, or the stage the service performs.</param>
/// <param name="TagsRequest">Whether the decorator names an attribute of the request.</param>
/// <param name="ObservesResult">Whether the decorator looks at what the handler returned.</param>
/// <param name="Dependencies">The services the hooks need.</param>
/// <param name="Members">Every member of the interface, those it inherits included.</param>
/// <param name="Methods">The ordinary methods among the members.</param>
/// <param name="Location">Where the entry is written.</param>
internal sealed record ObservedEntry(
	INamedTypeSymbol Service,
	string ClassName,
	ObservationKind Kind,
	string Name,
	bool TagsRequest,
	bool ObservesResult,
	INamedTypeSymbol[] Dependencies,
	ISymbol[] Members,
	IMethodSymbol[] Methods,
	LocationInfo Location);
