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

using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using ResponseParameters = Abblix.Oidc.Client.Features.Authorization.Responses.Parameters;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
        => handler.HandleAsync(ReadCallback(request), cancellationToken);

    /// <summary>
    /// Reads the callback parameters out of <paramref name="request"/>, refusing a response that arrived by
    /// a transport this client did not ask for.
    /// </summary>
    /// <param name="request">The callback request the provider redirected the browser to.</param>
    /// <returns>The parameters, ready for the framework-independent handler.</returns>
    /// <remarks>
    /// Public because the authentication handler needs the same reading and the same refusal, and a second
    /// copy of either is a second thing to keep in step.
    /// </remarks>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> ReadCallback(HttpRequest request)
    {
        RequireTheExpectedTransport(request);

        return ReadParameters(request);
    }

    /// <summary>
    /// Refuses a token-returning response that arrived in the query rather than as a posted form.
    /// </summary>
    /// <remarks>
    /// Multiple Response Type Encoding Practices section 5 says of every token-returning response type
    /// that "the query encoding MUST NOT be used", so a response carrying tokens in the query is one the
    /// provider was forbidden to send that way - a downgrade of the transport this client asked for.
    /// The check lives here rather than in the handler because only this layer can see the transport at
    /// all: <c>response_mode</c> is a request parameter and is not echoed back, so the mode a response
    /// arrived by is observable in the request itself and nowhere in the parameters.
    /// Its practical value is a legible failure. A host that misconfigured the mode would otherwise meet
    /// this as an empty callback (the fragment stripped before the request) or as a token silently taken
    /// from a place the specification forbids - both of which read as "the provider did not answer"
    /// rather than as what they are.
    /// </remarks>
    private static void RequireTheExpectedTransport(HttpRequest request)
    {
        // Nothing to compare against means no comparison, rather than a failure: this check exists to make
        // a misconfiguration legible, and it must not itself become one. The base handler still verifies
        // the artifacts against the flow, so a response is never accepted merely for having arrived.
        var options = request.HttpContext.RequestServices
            ?.GetService<IOptions<AuthorizationRequestOptions>>()?.Value;

        if (options is null || !options.Flow.ReturnsFrontChannelTokens())
            return;

        if (!string.Equals(options.ResponseMode, ResponseModes.FormPost, StringComparison.Ordinal))
            return;

        if (request.HasFormContentType)
            return;

        // An error response carries no token, so the prohibition this check enforces does not reach it -
        // Multiple Response Type Encoding Practices section 5 forbids the query encoding for a response
        // carrying tokens, and a refusal carries none. Providers do return errors by redirect, and a user
        // who pressed Cancel deserves to hear that rather than a complaint about the transport.
        if (request.Query.ContainsKey(ResponseParameters.Error))
            return;

        throw new AuthorizationResponseException(
            $"The '{options.Flow.ToResponseType()}' flow asked the provider to return its response as a "
            + "form post, and this callback did not arrive as one. Multiple Response Type Encoding "
            + "Practices section 5 forbids the query encoding for a response carrying tokens, so this is "
            + "not a response to read from the query instead.");
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
