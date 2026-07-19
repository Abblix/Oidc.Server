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
