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

using System.Net.Http.Headers;
using System.Net.Mime;

namespace Abblix.SharedSignals.Receiver.BackChannelLogout;

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
/// <param name="validator">The Logout Token's validation, which is Section 2.6.</param>
/// <param name="sink">Where the notification lands, which is Section 2.7.</param>
public sealed class BackChannelLogoutHandler(
    ILogoutTokenValidator validator,
    ILogoutNotificationSink sink)
{
    /// <summary>
    /// The single parameter the request must carry (Section 2.5).
    /// </summary>
    public const string LogoutTokenParameter = "logout_token";

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
        if (!MediaTypeHeaderValue.TryParse(contentType, out var mediaType)
            || !string.Equals(
                mediaType.MediaType,
                MediaTypeNames.Application.FormUrlEncoded,
                StringComparison.OrdinalIgnoreCase))
        {
            return BackChannelLogoutResult.BadRequest(
                $"The request arrived as '{contentType ?? "(no content type)"}', where OpenID Connect "
                + $"Back-Channel Logout 1.0 Section 2.5 requires "
                + $"'{MediaTypeNames.Application.FormUrlEncoded}'.");
        }

        if (ReadLogoutToken(body) is not { Length: > 0 } logoutToken)
        {
            return BackChannelLogoutResult.BadRequest(
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
            return BackChannelLogoutResult.BadRequest(exception.Message);
        }

        var refusal = await sink.ConsumeAsync(notification, cancellationToken);
        return refusal is null
            ? BackChannelLogoutResult.Ok
            : BackChannelLogoutResult.BadRequest(refusal);
    }

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
