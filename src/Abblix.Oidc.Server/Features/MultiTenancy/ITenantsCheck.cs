// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Judges a list of tenants, whichever way it arrives: the tenants the settings declare at startup, and the list
/// a change would leave.
/// </summary>
/// <remarks>
/// It names the tenants each refusal is about, so whoever asks can decide what a refusal costs: the settings
/// refuse to start, while a list read from a store leaves the refused tenants out.
/// <para>
/// A list read from a store is judged at every reading, so a check runs once a period. One that throws instead of
/// refusing fails the whole reading, and the server keeps serving the tenants it read last.
/// </para>
/// </remarks>
public interface ITenantsCheck
{
    /// <summary>
    /// What is wrong with <paramref name="tenants"/>, judged as the whole list the server would serve with the
    /// server's own settings <paramref name="options"/>.
    /// </summary>
    /// <remarks>
    /// The server's settings are handed in rather than read from the options pipeline, since the list the settings
    /// declare is judged while those very settings are being validated.
    /// </remarks>
    IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options);
}
