// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Why a check of a tenant list refuses some of its tenants.
/// </summary>
/// <param name="TenantIds">The tenants refused: one for a mistake of its own, every party to a conflict between
/// several.</param>
/// <param name="Message">What is wrong, naming the tenants.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed record TenantRefusal(IReadOnlyCollection<string> TenantIds, string Message)
{
    /// <summary>
    /// A refusal of <paramref name="tenant"/> alone.
    /// </summary>
    public static TenantRefusal Of(TenantDefinition tenant, string message) => new([tenant.Id], message);
}
