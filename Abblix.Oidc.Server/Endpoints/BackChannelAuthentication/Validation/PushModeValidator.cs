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

        // HTTPS enforcement per CIBA spec Section 10.3.1:
        // Push mode token delivery endpoint MUST use HTTPS for security
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
