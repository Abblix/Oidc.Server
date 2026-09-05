// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;

/// <summary>
/// Adds caching to <see cref="ICheckSessionResponseFormatter"/>, reusing the formatted result for a given cache key.
/// </summary>
public class CheckSessionResponseCachingDecorator(
    ICheckSessionResponseFormatter inner,
    ICheckSessionResponseCache cache) : ICheckSessionResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(CheckSessionResponse response)
        => cache.GetOrAddAsync(response.CacheKey, () => inner.FormatResponseAsync(response));
}
