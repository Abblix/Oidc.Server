// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// Marks a partial MVC model record whose members are produced by the MVC model source generator
/// from the given core model type: bound properties with model binders resolved from the core
/// wire-format markers, validation attributes translated to their executable MVC counterparts,
/// and the mapping method projecting the bound model back onto the core type.
/// </summary>
/// <param name="coreModelType">The core model type in <c>Abblix.Oidc.Server.Model</c> to generate from.</param>
[AttributeUsage(AttributeTargets.Class)]
public sealed class GeneratedFromAttribute(Type coreModelType) : Attribute
{
	/// <summary>
	/// The core model type the MVC model is generated from.
	/// </summary>
	public Type CoreModelType => coreModelType;

	/// <summary>
	/// Indicates that the endpoint accepts the request via HTTP GET as well, so every generated
	/// bound property carries the corresponding flag (e.g. the authorization and end-session endpoints).
	/// </summary>
	public bool SupportsGet { get; init; }
}
