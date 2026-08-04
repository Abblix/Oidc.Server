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
/// Declares that the model binder realises the given core wire-format marker from
/// <c>Abblix.Oidc.Server.DeclarativeBinding</c>. The MVC model source generator scans
/// the assembly for these declarations to build its marker-to-binder map, so the knowledge
/// of which binder parses which wire format lives here, next to the binders - the core
/// markers themselves stay purely semantic and binding-technology-free.
/// </summary>
/// <param name="formatAttributeType">The core wire-format marker attribute type this binder realises.</param>
[AttributeUsage(AttributeTargets.Class)]
public sealed class BindsAttribute(Type formatAttributeType) : Attribute
{
	/// <summary>
	/// The core wire-format marker attribute type this binder realises.
	/// </summary>
	public Type FormatAttributeType => formatAttributeType;
}
