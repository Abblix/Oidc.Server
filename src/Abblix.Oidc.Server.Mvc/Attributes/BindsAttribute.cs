// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
