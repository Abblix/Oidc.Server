// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
