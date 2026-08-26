// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates required parameters for CIBA push mode authentication requests.
/// Ensures that clients using push mode have proper HTTPS endpoint configuration.
/// </summary>
public class PushModeValidator : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Validates push mode specific requirements: backchannel_client_notification_endpoint must be
    /// present and use HTTPS.
    /// </summary>
    /// <param name="context">The validation context containing request and client information.</param>
    /// <returns>An error if validation fails, null if successful.</returns>
    public Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
    {
        // Only validate if client is configured for push mode
        if (context.ClientInfo.BackChannelTokenDeliveryMode != BackchannelTokenDeliveryModes.Push)
            return Task.FromResult<OidcError?>(null);

        // Push mode requires backchannel_client_notification_endpoint to be registered
        if (context.ClientInfo.BackChannelClientNotificationEndpoint == null)
        {
            return Task.FromResult<OidcError?>(new OidcError(
                ErrorCodes.InvalidClient,
                "The client is not configured with a backchannel_client_notification_endpoint"));
        }

        // CIBA Core 1.0 Section 9 states both rules in one sentence: "It MUST be an HTTPS URL and
        // Communication with the Client Notification Endpoint MUST utilize TLS." Only the first is a
        // property of the registered value and checkable here; the second is the transport the host
        // establishes when it calls the endpoint. Section 10.3.1 is about what is delivered and says
        // nothing about the scheme.
        if (!string.Equals(
            context.ClientInfo.BackChannelClientNotificationEndpoint.Scheme,
            Uri.UriSchemeHttps,
            StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<OidcError?>(new OidcError(
                ErrorCodes.InvalidClient,
                "The backchannel_client_notification_endpoint must use HTTPS for security"));
        }

        return Task.FromResult<OidcError?>(null);
    }
}
