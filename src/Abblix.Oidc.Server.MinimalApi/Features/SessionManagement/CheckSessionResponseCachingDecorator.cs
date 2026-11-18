// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.SessionManagement;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;

/// <summary>
/// Adds caching to <see cref="ICheckSessionResponseFormatter{IResult}"/>, reusing the formatted result for a given cache key.
/// </summary>
public class CheckSessionResponseCachingDecorator(
    ICheckSessionResponseFormatter<IResult> inner,
    ICheckSessionResponseCache<IResult> cache,
    ITenantAccessor tenantAccessor,
    ITenantCatalog catalog) : ICheckSessionResponseFormatter<IResult>
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(CheckSessionResponse response)
        => cache.GetOrAddAsync(response.CacheKey, () => inner.FormatResponseAsync(response), StoreTenantCatalog.ReleasedOf(catalog, tenantAccessor.CurrentTenant()));
}
