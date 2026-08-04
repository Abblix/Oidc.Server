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

using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates CIBA-related metadata (OpenID Connect Client-Initiated Backchannel Authentication 1.0 §4):
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

        // CIBA Core 1.0 §4: the notification endpoint MUST be an HTTPS URL (communication with it
        // MUST use TLS). Only ping/push reach here with an endpoint set - poll-with-endpoint and the
        // missing-endpoint cases are already rejected above.
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
