// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates CIBA-related metadata (OpenID Connect Client-Initiated Backchannel Authentication 1.0, section 4):
/// the consistency between <c>backchannel_token_delivery_mode</c> and
/// <c>backchannel_client_notification_endpoint</c>, and that
/// <c>backchannel_authentication_request_signing_alg</c> is on the server's supported list.
/// </summary>
/// <param name="jwtValidator">Source of supported JWT signing algorithms.</param>
public class BackChannelAuthenticationValidator(IJsonWebTokenValidator jwtValidator)
    : IClientRegistrationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Applies the CIBA consistency rules: <c>poll</c> must not include a notification endpoint;
    /// <c>ping</c> and <c>push</c> must include one; the signing algorithm, when present, must
    /// be supported.
    /// </summary>
    private OidcError? Validate(ClientRegistrationValidationContext context)
    {
        switch (context.Request)
        {
            case { BackChannelTokenDeliveryMode: null }:
                return null;

            case {
                BackChannelTokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
                BackChannelClientNotificationEndpoint: not null,
            }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "Notification endpoint is invalid if the token delivery mode is set to poll");

            case {
                BackChannelTokenDeliveryMode:
                    BackchannelTokenDeliveryModes.Ping or
                    BackchannelTokenDeliveryModes.Push,
                BackChannelClientNotificationEndpoint: null,
            }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "Notification endpoint is required if the token delivery mode is set to ping or push");

            case {
                BackChannelTokenDeliveryMode: not (
                    BackchannelTokenDeliveryModes.Poll or
                    BackchannelTokenDeliveryModes.Ping or
                    BackchannelTokenDeliveryModes.Push),
            }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "The specified token delivery mode is not supported");
        }

        // CIBA Core 1.0 section 4, describing backchannel_client_notification_endpoint as registration
        // metadata: "It MUST be an HTTPS URL." That is the whole of what section 4 says about it, and it
        // is also the whole of what is checkable at registration - the registered value is all there is
        // here.
        //
        // The TLS half belongs to section 9, which restates the HTTPS rule and adds "Communication with
        // the Client Notification Endpoint MUST utilize TLS". PingModeValidator and PushModeValidator
        // quote section 9 because they run when the endpoint is about to be called; this runs when it is
        // being registered, and nothing has called anything yet. Attributing the TLS clause to section 4
        // sends a reader to a section that does not contain it.
        //
        // Only ping/push reach here with an endpoint set - poll-with-endpoint and the missing-endpoint
        // cases are already rejected above.
        var notificationEndpoint = context.Request.BackChannelClientNotificationEndpoint;
        if (notificationEndpoint != null && notificationEndpoint.Scheme != Uri.UriSchemeHttps)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The backchannel_client_notification_endpoint must use the HTTPS scheme");
        }

        var signingAlgorithm = context.Request.BackChannelAuthenticationRequestSigningAlg;
        if (signingAlgorithm.HasValue() &&
            !jwtValidator.SigningAlgorithmsSupported.Contains(signingAlgorithm, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The specified signing algorithm is not supported");
        }

        return null;
    }
}
