// Abblix OIDC Client Library
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

using Abblix.Oidc.Client.Features.Authorization.Responses;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Runs the authorization callback handler against an <see cref="HttpRequest"/>, marshalling its
/// parameters into the shape the handler reads.
/// </summary>
public static class AuthorizationResponseHandlerExtensions
{
    /// <summary>
    /// Handles the callback carried by <paramref name="request"/>: reads its parameters and runs them
    /// through the same checks the handler applies to any authorization response.
    /// </summary>
    /// <param name="handler">The handler that parses, verifies and consumes the response.</param>
    /// <param name="request">The callback request the provider redirected the browser to.</param>
    /// <param name="cancellationToken">Cancels the store and metadata reads the handler makes.</param>
    /// <returns>The artifacts the flow returned, validated, together with the login they belong to.</returns>
    /// <remarks>
    /// This is the only ASP.NET the callback handling needs: everything after the parameters are read is
    /// the framework-independent handler's, so the whole trust pipeline - parse, consume state, check
    /// issuer, act - is shared with any other host that can produce the same parameter map.
    /// </remarks>
    public static Task<AuthorizationResult> HandleAsync(
        this IAuthorizationResponseHandler handler,
        HttpRequest request,
        CancellationToken cancellationToken = default)
    {
        return handler.HandleAsync(ReadParameters(request), cancellationToken);
    }

    /// <summary>
    /// Reads the response parameters from wherever the response mode put them: a posted form when the
    /// provider used <c>form_post</c>, the query string otherwise.
    /// </summary>
    /// <remarks>
    /// Every value under a name is kept, not just the first. A callback that repeats a parameter is one
    /// the handler must refuse (RFC 6749 section 3.1), so flattening a repeat to a single value here
    /// would decide, silently and in the framework layer, exactly the question an attacker would want
    /// decided - which of two codes is used. The map hands both to the handler to reject.
    /// </remarks>
    private static IReadOnlyDictionary<string, IReadOnlyList<string>> ReadParameters(HttpRequest request)
    {
        // A form_post response arrives as an application/x-www-form-urlencoded POST; every other mode this
        // client uses returns the parameters in the query. HasFormContentType is what tells them apart.
        var source = request.HasFormContentType
            ? (IEnumerable<KeyValuePair<string, StringValues>>)request.Form
            : request.Query;

        return source.ToDictionary(
            entry => entry.Key,
            // A value with no '=' (e.g. "?state") reads as null in StringValues; keep it as an empty
            // string rather than dropping it, so a repeated parameter stays a count of two and reaches
            // the handler's duplicate check intact.
            entry => (IReadOnlyList<string>)entry.Value.Select(value => value ?? string.Empty).ToArray(),
            StringComparer.Ordinal);
    }
}
