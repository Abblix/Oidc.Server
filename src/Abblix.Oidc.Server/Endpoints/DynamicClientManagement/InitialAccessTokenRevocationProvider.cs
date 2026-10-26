// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default implementation that checks revocation against the subjects the tenant lists in
/// <see cref="TenantDefinition.RevokedInitialAccessTokenSubjects"/>.
/// For production use with large or dynamic revocation lists, replace with a database- or cache-backed implementation.
/// </summary>
public class InitialAccessTokenRevocationProvider : IInitialAccessTokenRevocationProvider
{
    /// <inheritdoc />
    public Task<bool> IsRevokedAsync(TenantDefinition tenant, string subject)
        => Task.FromResult(tenant.RevokedInitialAccessTokenSubjects.Contains(subject, StringComparer.Ordinal));
}
