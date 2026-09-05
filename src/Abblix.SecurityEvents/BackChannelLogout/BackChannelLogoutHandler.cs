// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net.Http.Headers;
using System.Net.Mime;
using Microsoft.Extensions.Logging;

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// Takes one back-channel logout request from the transport and answers it: reads the
/// <c>logout_token</c> out of the posted form, puts it through the receiver's profile, hands the
/// notification to the application, and shapes the response
/// (OpenID Connect Back-Channel Logout 1.0 Sections 2.5 and 2.8).
/// </summary>
/// <remarks>
/// Transport-neutral, like the push intake beside it: it takes the two things any adapter has -
/// the content type and the body - and returns a result the adapter renders. That keeps the
/// specification's request and response rules in one place rather than in each host framework's
/// endpoint.
/// </remarks>
/// <param name="logger">Records every refusal, which no other party keeps.</param>
/// <param name="validator">The Logout Token's validation, which is Section 2.6.</param>
/// <param name="sink">Where the notification lands, which is Section 2.7.</param>
public sealed partial class BackChannelLogoutHandler(
    ILogger<BackChannelLogoutHandler> logger,
    ILogoutTokenValidator validator,
    ILogoutNotificationSink sink)
{
    /// <summary>
    /// The single parameter the request must carry (Section 2.5).
    /// </summary>
    private const string LogoutTokenParameter = "logout_token";

    /// <summary>
    /// Handles one logout request.
    /// </summary>
    /// <param name="contentType">The request's Content-Type header, as received.</param>
    /// <param name="body">The request body: a form-encoded parameter list.</param>
    /// <param name="cancellationToken">Cancels validation I/O and processing.</param>
    public async Task<BackChannelLogoutResult> HandleAsync(
        string? contentType,
        string? body,
        CancellationToken cancellationToken = default)
    {
        // "The POST body uses the application/x-www-form-urlencoded encoding" (Section 2.5) -
        // parsed as a media type, so a parameter like charset does not fail a conformant provider.
        if (!MediaTypeHeaderValue.TryParse(contentType, out var mediaType) ||
            !string.Equals(
                mediaType.MediaType,
                MediaTypeNames.Application.FormUrlEncoded,
                StringComparison.OrdinalIgnoreCase))
        {
            return Refuse(
                $"The request arrived as '{contentType ?? "(no content type)"}', where OpenID Connect "
                + $"Back-Channel Logout 1.0 Section 2.5 requires "
                + $"'{MediaTypeNames.Application.FormUrlEncoded}'.");
        }

        if (ReadLogoutToken(body) is not { Length: > 0 } logoutToken)
        {
            return Refuse(
                $"The request carries no '{LogoutTokenParameter}' parameter, which Section 2.5 requires.");
        }

        LogoutNotification notification;
        try
        {
            notification = await validator.ValidateAsync(logoutToken, cancellationToken);
        }
        catch (LogoutTokenValidationException exception)
        {
            // "If any of the validation steps fails, reject the Logout Token and return an HTTP
            // 400 Bad Request error" (Section 2.6). The reason travels in the description, which
            // Section 2.8 exists to help debug deployments with.
            return Refuse(exception.Message);
        }

        var refusal = await sink.ConsumeAsync(notification, cancellationToken);
        return refusal is null ? BackChannelLogoutResult.Ok : Refuse(refusal);
    }

    /// <summary>
    /// Shapes a refusal and records it.
    /// </summary>
    /// <remarks>
    /// Recorded here because here is where the description exists. It travels to the provider in
    /// the response, which Section 2.8 asks for so a deployment can be debugged - but the provider
    /// is the other party, and the receiver that refused keeps nothing. A run of refusals is a
    /// provider signing with keys this receiver does not trust, a receiver reading a JWK Set that
    /// is reachable but wrong, or a malformed request, and the three are told apart only by the
    /// description; without it an operator sees an even stream of 400s and no way in. A key
    /// document that cannot be fetched at all is a different signal - that throws, and answers 500
    /// rather than arriving here.
    /// <para>
    /// One place, so every refusal path is recorded by construction rather than by each of them
    /// remembering - and a path added later is recorded on the day it is written.
    /// </para>
    /// </remarks>
    /// <param name="description">What was wrong, in the words that go back to the provider.</param>
    private BackChannelLogoutResult Refuse(string description)
    {
        // The code is the constant every refusal carries, taken from the constant rather than read
        // back off the result: the result's error is nullable, and dereferencing it here would
        // assert a fact the compiler cannot check in order to learn something already known.
        LogRefused(BackChannelLogoutError.InvalidRequest, Abbreviate(description));

        return BackChannelLogoutResult.BadRequest(description);
    }

    /// <summary>How much of a description is worth keeping in a log line.</summary>
    /// <remarks>
    /// This endpoint is unauthenticated by design, and one refusal path echoes the request's own
    /// Content-Type into the description - so an anonymous caller chooses both the rate and, up to
    /// the server's header limit, the size of what is written. The response still carries the whole
    /// text to the provider, which is what Section 2.8 asks for; the log keeps the part that names
    /// the problem.
    /// </remarks>
    private const int LoggedDescriptionLimit = 512;

    private static string Abbreviate(string description)
        => description.Length <= LoggedDescriptionLimit
            ? description
            : description[..LoggedDescriptionLimit] + "...";

    /// <summary>
    /// Reads the one parameter this endpoint understands out of a form-encoded body.
    /// </summary>
    /// <remarks>
    /// Everything else is dropped without a word, which Section 2.5 requires: "The POST body MAY
    /// contain other values in addition to logout_token. Values that are not understood by the
    /// implementation MUST be ignored." So an unknown parameter is not a reason to refuse, and a
    /// stricter reading would break a provider that sends one.
    /// <para>
    /// Parsed here rather than taken from a framework's form collection, so the handler stays
    /// usable from any adapter. Form encoding writes a space as '+', which percent-decoding alone
    /// does not undo - a Logout Token cannot contain one, being base64url, but the values around
    /// it can, and a parser that is right only for its own parameter is a trap for the next one.
    /// </para>
    /// </remarks>
    private static string? ReadLogoutToken(string? body)
    {
        if (string.IsNullOrEmpty(body))
            return null;

        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            if (separator < 0)
                continue;

            if (Decode(pair[..separator]) == LogoutTokenParameter)
                return Decode(pair[(separator + 1)..]);
        }

        return null;

        static string Decode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
    }
}
