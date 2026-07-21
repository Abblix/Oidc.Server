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


using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <remarks>
/// No message here ever takes the token value as a parameter, and none ever should: a log is somewhere a
/// bearer credential must not end up, and a structured logger will happily ship whatever it is handed to
/// wherever logs go.
/// </remarks>
partial class AccessTokenHandler
{
    [LoggerMessage(
        EventId = LogEvents.ProtectedResources.AccessTokenAttached,
        Level = LogLevel.Debug,
        Message = "Presented an access token to {Destination} as {Scheme}")]
    private partial void LogAccessTokenAttached(Uri destination, string scheme);

    [LoggerMessage(
        EventId = LogEvents.ProtectedResources.ResourceRefusedToken,
        Level = LogLevel.Warning,
        Message = "The resource at {Destination} refused the access token with status {StatusCode}, "
                  + "error {Error} and required scope {RequiredScope}")]
    private partial void LogResourceRefusedToken(
        Uri destination, int statusCode, string? error, string? requiredScope);

    [LoggerMessage(
        EventId = LogEvents.ProtectedResources.AuthorizedUriChanged,
        Level = LogLevel.Warning,
        Message = "The request authorized for {AuthorizedDestination} ended at {FinalDestination}. A "
                  + "redirect was followed and the Authorization header was stripped, so a refusal from "
                  + "there is not an expired token")]
    private partial void LogAuthorizedUriChanged(Uri authorizedDestination, Uri finalDestination);
}
