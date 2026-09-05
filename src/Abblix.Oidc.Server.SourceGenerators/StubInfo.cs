// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.SourceGenerators;

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
