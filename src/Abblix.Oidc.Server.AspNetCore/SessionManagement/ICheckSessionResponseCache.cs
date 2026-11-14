// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.AspNetCore.SessionManagement;

/// <summary>
/// Keeps the formatted check-session page of each issuer, so it is rendered once rather than on every request.
/// </summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface ICheckSessionResponseCache<TResult> where TResult : class
{
    /// <summary>
    /// Gets the result cached under <paramref name="key"/>, or adds the one <paramref name="factory"/> produces.
    /// </summary>
    /// <param name="key">The key used to identify the item in the cache.</param>
    /// <param name="factory">Produces the result to cache when none is cached under the key.</param>
    /// <param name="released">Canceled once the issuer the result is for is gone for good, which drops it.
    /// </param>
    /// <returns>The cached or newly produced result.</returns>
    Task<TResult> GetOrAddAsync(object key, Func<Task<TResult>> factory, CancellationToken released);
}
