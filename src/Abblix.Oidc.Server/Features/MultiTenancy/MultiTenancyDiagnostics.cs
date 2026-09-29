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
/// Experimental until every per-tenant store, setting and key is separated: until then a tenant's data is not
/// yet kept apart from the others', and the diagnostic makes a host opt in knowingly.
/// </remarks>
public static class MultiTenancyDiagnostics
{
    /// <summary>
    /// The diagnostic id every multi-tenancy type and entry point carries.
    /// </summary>
    public const string Experimental = "ABXMT001";
}
