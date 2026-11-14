// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Marks a type the entity storage writes as JSON on purpose, with no Protocol Buffers codec.
/// </summary>
/// <remarks>
/// JSON carries no field numbers, so two versions of the server running side by side can misread each other's
/// records of such a type. ABX1009 refuses every other stored type without a codec, so the exception stands in the
/// code with its reason rather than in a log warning.
/// </remarks>
/// <param name="reason">Why the type is stored as JSON.</param>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = false)]
internal sealed class StoredAsJsonAttribute(string reason) : Attribute
{
    /// <summary>
    /// Why the type is stored as JSON.
    /// </summary>
    public string Reason => reason;
}
