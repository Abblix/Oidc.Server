// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The diagnostic that marks multi-tenancy experimental.
/// </summary>
/// <remarks>
/// Experimental while the multi-tenancy API takes in what its first hosts need: its types and members may still change
/// without the overloads a stable API keeps, and the diagnostic makes a host opt in knowingly. A tenant's data is kept
/// apart from the others' in the server's own stores, settings and keys; the users and the consents stay the host's.
/// </remarks>
public static class MultiTenancyDiagnostics
{
    /// <summary>
    /// The diagnostic id every multi-tenancy type and entry point carries.
    /// </summary>
    public const string Experimental = "ABXMT001";
}
