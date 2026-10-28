// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ScopeManagement;

/// <summary>
/// Descriptions of a refused scope that every endpoint checking the scope gives alike.
/// </summary>
internal static class ScopeRefusals
{
    /// <summary>
    /// A request naming no scope from a client required to name one.
    /// </summary>
    public const string NoneNamed = "This client is required to name the scope it requests";

    /// <summary>
    /// A token request naming none of the scopes its grant holds.
    /// </summary>
    public const string NotGranted = "The requested scope exceeds the scope granted by the resource owner.";
}
