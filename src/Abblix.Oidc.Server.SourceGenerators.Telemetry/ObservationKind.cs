// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.SourceGenerators.Telemetry;

/// <summary>
/// What a generated decorator observes, which decides what it is built from and what it records.
/// </summary>
internal enum ObservationKind
{
	/// <summary>
	/// An endpoint's handling: a span of the endpoint, the request's measurements, and optional hooks.
	/// </summary>
	Endpoint,

	/// <summary>
	/// A stage of handling a request: a child span under the endpoint's span, and nothing else.
	/// </summary>
	Stage,
}
