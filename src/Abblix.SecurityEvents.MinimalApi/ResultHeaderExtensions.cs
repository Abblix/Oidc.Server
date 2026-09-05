// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.AspNetCore.Http;

namespace Abblix.SecurityEvents.MinimalApi;

/// <summary>
/// Attaches response headers to a result instead of writing them beside it.
/// </summary>
public static class ResultHeaderExtensions
{
    /// <summary>
    /// Returns a result that sets the given headers and then renders
    /// <paramref name="result"/>.
    /// </summary>
    /// <remarks>
    /// A header a specification requires belongs to the answer, not to the code path that happened
    /// to produce it. Written as a statement before the return, it is attached to whichever branch
    /// the author was looking at and quietly missing from the others - and a header required on a
    /// refusal is required on the branch least often read. Carried by the result, it travels with
    /// every answer that result stands for.
    /// <para>
    /// The headers are set when the result is executed, which is before anything is written to the
    /// body: a header added after the response has started is dropped, and ASP.NET Core reports
    /// that as an exception rather than as the silent loss it would otherwise be.
    /// </para>
    /// </remarks>
    /// <param name="result">The answer being rendered.</param>
    /// <param name="configure">Sets the headers on the response.</param>
    public static IResult WithHeaders(this IResult result, Action<IHeaderDictionary> configure)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(configure);

        return new HeadersAttachedDecorator(result, configure);
    }

    /// <param name="inner">The answer being rendered.</param>
    /// <param name="configure">Sets the headers on the response.</param>
    private sealed class HeadersAttachedDecorator(IResult inner, Action<IHeaderDictionary> configure) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            ArgumentNullException.ThrowIfNull(httpContext);

            configure(httpContext.Response.Headers);
            return inner.ExecuteAsync(httpContext);
        }
    }
}
