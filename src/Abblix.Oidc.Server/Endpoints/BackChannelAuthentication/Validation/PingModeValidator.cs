// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates required parameters for CIBA ping mode authentication requests.
/// Ensures that clients using ping mode have proper configuration and provide necessary tokens.
/// </summary>
public class PingModeValidator : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Validates ping mode specific requirements: client_notification_token and
    /// backchannel_client_notification_endpoint must be present.
    /// </summary>
    /// <param name="context">The validation context containing request and client information.</param>
    /// <returns>An error if validation fails, null if successful.</returns>
    public Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
    {
        // Only validate if client is configured for ping mode
        if (context.ClientInfo.BackChannelTokenDeliveryMode != BackchannelTokenDeliveryModes.Ping)
            return Task.FromResult<OidcError?>(null);

        // Ping mode requires client_notification_token in the request
        if (!context.Request.ClientNotificationToken.HasValue())
        {
            return Task.FromResult<OidcError?>(new OidcError(
                ErrorCodes.InvalidRequest,
                "The client_notification_token parameter is required for ping mode"));
        }

        // Ping mode requires backchannel_client_notification_endpoint to be registered
        if (context.ClientInfo.BackChannelClientNotificationEndpoint == null)
        {
            return Task.FromResult<OidcError?>(new OidcError(
                ErrorCodes.InvalidClient,
                "The client is not configured with a backchannel_client_notification_endpoint"));
        }

        // CIBA Core 1.0 Section 4 defines backchannel_client_notification_endpoint and says of it:
        // "It MUST be an HTTPS URL." The same paragraph adds that communication with the endpoint
        // MUST use TLS, which is the transport rather than the registered value and is the host's.
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
