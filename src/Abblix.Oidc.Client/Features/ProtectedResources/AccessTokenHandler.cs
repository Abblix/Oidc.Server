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

using System.Net;
using System.Net.Http.Headers;
using Abblix.Oidc.Client.Common.Constants;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// Presents this client's access token on outgoing calls to one protected resource
/// (RFC 6750 section 2.1).
/// </summary>
/// <remarks>
/// The token goes on each request rather than on the client's default headers, because a message handler is
/// pooled and reused across users for minutes at a time: a token written into
/// <c>HttpClient.DefaultRequestHeaders</c> is captured when the client is built and handed to whoever calls
/// next.
/// For the same reason this handler holds no state of its own. Everything user-specific is read per call
/// through the source, which is where ambient state belongs.
/// It does not retry, refresh, or cache. RFC 6750 section 3.1 makes retrying a MAY, the request body is a
/// forward-only stream so a retry usually cannot resend it anyway, and a refresh done here would race every
/// other in-flight request for a rotating refresh token - losing that race consumes the token, which a
/// provider is entitled to answer by revoking the whole grant (RFC 9700 section 4.14.2). A host that wants
/// any of it puts it behind <see cref="IAccessTokenSource"/>, where it can be done once, with the host's own
/// storage.
/// </remarks>
/// <param name="logger">Records what was presented and what came back, never the token itself.</param>
/// <param name="source">Supplies the token for each call.</param>
/// <param name="options">Names the resource this client is allowed to talk to.</param>
internal sealed partial class AccessTokenHandler(
    ILogger<AccessTokenHandler> logger,
    IAccessTokenSource source,
    ProtectedResourceOptions options) : DelegatingHandler
{
    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var resource = options.Resource
                       ?? throw new AccessTokenPresentationException(
                           $"{nameof(ProtectedResourceOptions)}.{nameof(ProtectedResourceOptions.Resource)} "
                           + "is not set, so there is no resource this client is allowed to talk to.");

        // The absolute address, which HttpClient has already produced by merging its BaseAddress before the
        // pipeline runs. Checking anything before this point would check a value the request will not use.
        var destination = request.RequestUri;

        if (destination is null || !destination.IsAbsoluteUri)
        {
            throw new AccessTokenPresentationException(
                "The request has no absolute address, so where the token would be sent is unknown.");
        }

        RequireSecureTransport(destination);
        RequireAuthorizedDestination(resource, destination);
        RequireNoCredentialAlready(request);

        // Only now. A destination this client refuses must never cause a token to be produced: a source may
        // mint, unseal or refresh one, and doing that for a request that will not be sent is work done on
        // behalf of a mistake.
        var token = await source.GetTokenAsync(
            new AccessTokenRequest(resource, options.Scopes, destination), cancellationToken);

        Present(request, token);
        LogAccessTokenAttached(destination, token.Scheme);

        var response = await base.SendAsync(request, cancellationToken);

        ReportOutcome(response, destination);

        return response;
    }

    /// <summary>
    /// Refuses a destination that is not HTTPS.
    /// </summary>
    /// <remarks>
    /// RFC 6750 section 5.3 puts it as an obligation on the client: "Always use TLS (https)". There is no
    /// development or loopback exception here, deliberately. Its only correct setting is off, and the host
    /// that turns it on will not be the host that discovers a token in a proxy log. Local development has
    /// <c>dotnet dev-certs</c>; a TLS-terminating proxy has forwarded headers.
    /// </remarks>
    private static void RequireSecureTransport(Uri destination)
    {
        if (!string.Equals(destination.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new AccessTokenPresentationException(
                $"This client will not send an access token to '{destination.Scheme}://'. A bearer token is "
                + "usable by anyone who reads it, so it travels over HTTPS only (RFC 6750 section 5.3).");
        }
    }

    /// <summary>
    /// Refuses a destination outside the resource this client was registered for.
    /// </summary>
    /// <remarks>
    /// Ours rather than a clause, and the reason is what a bearer token is: whoever receives one can use it.
    /// A client whose base address was mistyped, or which was handed an absolute address by a caller, would
    /// otherwise deliver this user's credential to a stranger and receive a perfectly ordinary-looking reply.
    /// The comparison is exact on origin and then on a path prefix broken at a segment boundary.
    /// <see cref="Uri.IsBaseOf"/> is deliberately not used: it discards everything after the final slash, so
    /// <c>https://api.example.com/v1</c> would be a base of <c>https://api.example.com/anything</c>. Nor is
    /// a string prefix used on the whole address, which would make <c>https://api.example.com.attacker.test</c>
    /// a match for <c>https://api.example.com</c>.
    /// </remarks>
    private static void RequireAuthorizedDestination(Uri resource, Uri destination)
    {
        var sameOrigin =
            string.Equals(resource.Scheme, destination.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(resource.Host, destination.Host, StringComparison.OrdinalIgnoreCase)
            && resource.Port == destination.Port;

        // The trailing slash is what breaks the comparison at a segment boundary, so that a resource of
        // "/orders" does not authorize "/orders-admin".
        var resourcePath = resource.AbsolutePath.TrimEnd('/');
        var destinationPath = destination.AbsolutePath;

        var withinPath = resourcePath.Length == 0
                         || string.Equals(destinationPath, resourcePath, StringComparison.Ordinal)
                         || destinationPath.StartsWith(resourcePath + "/", StringComparison.Ordinal);

        if (!sameOrigin || !withinPath)
        {
            throw new AccessTokenPresentationException(
                $"This client presents its access token to '{resource}' only, and the request is addressed "
                + $"to '{destination}'. The token is not sent.");
        }
    }

    /// <summary>
    /// Refuses a request that already carries a credential.
    /// </summary>
    /// <remarks>
    /// RFC 6750 section 2: "Clients MUST NOT use more than one method to transmit the token in each
    /// request." Overwriting what a caller set would also be the wrong answer to a caller who meant it -
    /// they are calling the resource as someone else, and silently substituting this user's token is worse
    /// than refusing.
    /// The query string is checked for the same reason, and it is the one this client will never produce
    /// itself: section 2.3's URI-query method is one RFC 9700 section 4.3.2 turns into a MUST NOT, so a
    /// token found there came from a caller who built the address by hand.
    /// </remarks>
    private static void RequireNoCredentialAlready(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not null)
        {
            throw new AccessTokenPresentationException(
                "The request already carries an Authorization header. RFC 6750 section 2 allows one method "
                + "per request, so this client refuses rather than replacing what the caller set.");
        }

        if (request.RequestUri?.Query.Contains("access_token=", StringComparison.OrdinalIgnoreCase) is true)
        {
            throw new AccessTokenPresentationException(
                "The request address carries an access_token query parameter. That transmission method is a "
                + "MUST NOT (RFC 9700 section 4.3.2), and a second credential is not allowed beside it.");
        }
    }

    /// <summary>
    /// Puts the token on the request under its own scheme.
    /// </summary>
    /// <remarks>
    /// An exhaustive switch with a loud default, so a scheme this client cannot present fails by name rather
    /// than being sent as a Bearer token and refused by the resource server for reasons nobody can read.
    /// </remarks>
    /// <remarks>
    /// RFC 6750 defines three ways to transmit a bearer token, and this client implements the first only.
    /// The other two are decided against here rather than merely absent, so that the next reader does not
    /// take the gap for an oversight and close it.
    ///
    /// Section 2.2, the form-encoded body: "SHOULD NOT be used except in application contexts where
    /// participating browsers do not have access to the Authorization request header field". That exception
    /// is not this client. It runs on a server - in a web application or a background service - and an
    /// <see cref="HttpClient"/> can always set the header, so the condition the RFC carves the exception out
    /// for never arises here, and using the method anyway would be going against a SHOULD NOT with no reason
    /// to offer.
    /// The method also costs more than it looks. Section 2.2 admits it only when the entity-body is
    /// form-encoded, single-part and entirely ASCII, and when the HTTP method has body semantics at all.
    /// A service calling a JSON API meets none of that: adding an access_token field to a JSON body does not
    /// produce a request with a token in it, it produces a corrupted body. So the method is unavailable
    /// exactly where a server-side client would want it, which is worth saying plainly for anyone weighing
    /// it for a microservice.
    ///
    /// Section 2.3, the URI query: "Because of the security weaknesses associated with the URI method (see
    /// Section 5), including the high likelihood that the URL containing the access token will be logged, it
    /// SHOULD NOT be used unless it is impossible to transport the access token in the 'Authorization'
    /// request header field or the HTTP request entity-body." RFC 9700 section 4.3.2 goes further and makes
    /// it a MUST NOT. Note what section 2.3 ranks: the body method above the query one, so even the RFC's
    /// own ordering treats the query as the last resort - and this client is never in the position of having
    /// no alternative.
    /// Neither is offered behind a flag. A setting whose only correct value is off is a setting somebody
    /// turns on, and the person who turns it on is not the person who later finds the token in a proxy log.
    /// </remarks>
    private static void Present(HttpRequestMessage request, AccessToken token)
    {
        RequireWellFormed(token.Value);

        switch (token.Scheme)
        {
            case TokenTypes.Bearer:
                request.Headers.Authorization =
                    new AuthenticationHeaderValue(TokenTypes.Bearer, token.Value);
                break;

            case TokenTypes.DPoP:
                throw new AccessTokenPresentationException(
                    "The token source returned a DPoP token. Presenting one needs a proof JWT over the "
                    + "method, the address and a hash of the token (RFC 9449 section 4), which this client "
                    + "does not issue.");

            default:
                throw new AccessTokenPresentationException(
                    $"The token source returned scheme '{token.Scheme}', which this client cannot present.");
        }
    }

    /// <summary>
    /// Refuses a token value outside the grammar RFC 6750 section 2.1 defines for it.
    /// </summary>
    /// <remarks>
    /// Diagnosis rather than defence. <see cref="AuthenticationHeaderValue"/> already refuses the characters
    /// that could inject a header, so what this buys is a named exception naming the source instead of a
    /// bare format error from deep in the stack, plus refusing values that are header-legal and
    /// grammar-illegal - a source returning a JSON fragment, say, because someone stored the whole token
    /// response.
    /// </remarks>
    private static void RequireWellFormed(string value)
    {
        if (value.Length == 0 || !value.All(IsTokenCharacter))
        {
            throw new AccessTokenPresentationException(
                "The token source returned a value outside the b64token grammar of RFC 6750 section 2.1, so "
                + "it is not an access token this client will present.");
        }
    }

    /// <summary>
    /// The b64token character set of RFC 6750 section 2.1, padding included.
    /// </summary>
    private static bool IsTokenCharacter(char character)
        => char.IsAsciiLetterOrDigit(character) || character is '-' or '.' or '_' or '~' or '+' or '/' or '=';

    /// <summary>
    /// Records what the resource server answered, when it is worth knowing.
    /// </summary>
    /// <remarks>
    /// The response itself is returned untouched. What is added is the one line worth having at three in the
    /// morning: whether the refusal was the token being rejected or merely insufficient, and which scopes
    /// would have done - two situations with the same status family and completely different answers.
    /// </remarks>
    private void ReportOutcome(HttpResponseMessage response, Uri authorizedDestination)
    {
        // A redirect followed below this handler arrives with the Authorization header already stripped by
        // the runtime, which is correct and must never be "fixed": re-attaching credentials across a
        // redirect is a published vulnerability class. What it produces is a 401 that reads exactly like an
        // expired token, so the fact that the address moved is worth saying out loud.
        var finalDestination = response.RequestMessage?.RequestUri;
        if (finalDestination is not null && finalDestination != authorizedDestination)
            LogAuthorizedUriChanged(authorizedDestination, finalDestination);

        if (response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden))
            return;

        var challenge = BearerChallenge.Read(response.Headers.WwwAuthenticate);

        LogResourceRefusedToken(
            authorizedDestination,
            (int)response.StatusCode,
            challenge?.Error,
            challenge is { Scope.Count: > 0 } ? string.Join(' ', challenge.Scope) : null);
    }
}
