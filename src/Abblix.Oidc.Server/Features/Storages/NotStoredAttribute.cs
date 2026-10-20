// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Marks a property of a stored type that its Protocol Buffers message leaves out on purpose.
/// </summary>
/// <remarks>
/// ABX1010 refuses every other property a mapper does not carry both ways, since such a property is lost on every
/// write with nothing to report it, so the exception stands in the code with its reason.
/// </remarks>
/// <param name="reason">Why the property is not stored.</param>
[AttributeUsage(AttributeTargets.Property, Inherited = false)]
internal sealed class NotStoredAttribute(string reason) : Attribute
{
    /// <summary>
    /// Why the property is not stored.
    /// </summary>
    public string Reason => reason;
}
