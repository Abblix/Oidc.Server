// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Features.SessionManagement;

/// <summary>
/// Represents a cache for storing and retrieving Check Session response data.
/// </summary>
public interface ICheckSessionResponseCache
{
    /// <summary>
    /// Gets an ActionResult from the cache with the specified key, or adds it to the cache if not present.
    /// </summary>
    /// <param name="key">The key used to identify the item in the cache.</param>
    /// <param name="factory">
    /// A delegate that provides the ActionResult to be added to the cache if it doesn't exist.
    /// </param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> representing the asynchronous operation. The task result contains
    /// the cached or newly generated ActionResult.
    /// </returns>
    Task<ActionResult> GetOrAddAsync(object key, Func<Task<ActionResult>> factory);
}
