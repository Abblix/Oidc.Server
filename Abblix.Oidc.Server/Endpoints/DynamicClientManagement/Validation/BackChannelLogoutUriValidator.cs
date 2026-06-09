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
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the OIDC Back-Channel Logout 1.0 <c>backchannel_logout_uri</c>: when supplied it must be an
/// absolute URI that the server is permitted to fetch under the active SSRF policy
/// (<see cref="SecureHttpFetchOptions"/>). Because the OP itself POSTs the logout token to this endpoint,
/// rejecting an internal/loopback or disallowed-scheme target at registration stops a registered client
/// from becoming a (blind) SSRF vector and surfaces the problem to the caller up front rather than as a
/// silent delivery failure at logout time. The outbound handler still re-validates at request time.
/// </summary>
/// <param name="uriValidator">The shared SSRF URI policy used by the outbound HTTP handler.</param>
public class BackChannelLogoutUriValidator(ISecureUriValidator uriValidator)
    : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error if <c>backchannel_logout_uri</c> is relative or
    /// violates the SSRF policy; <c>null</c> when absent or compliant.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var uri = context.Request.BackChannelLogoutUri;
        if (uri == null)
            return null;

        if (!uri.IsAbsoluteUri)
            return ErrorFactory.InvalidClientMetadata(
                $"The {Parameters.BackChannelLogoutUri} is not an absolute URI");

        var rejection = uriValidator.Validate(uri);
        if (rejection != null)
            return ErrorFactory.InvalidClientMetadata(
                $"The {Parameters.BackChannelLogoutUri} is not allowed: {rejection}");

        return null;
    }
}
