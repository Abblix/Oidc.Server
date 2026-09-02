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


namespace Abblix.Oidc.Client;

/// <summary>
/// The event identifiers this assembly logs under.
/// </summary>
/// <remarks>
/// Numbers rather than message text, because a dashboard or an alert keys off the identifier: the wording of
/// a message may be improved at any time, and an event that changed its number underneath a running alert
/// would silence it without anyone noticing.
/// </remarks>
public static class LogEvents
{
    /// <summary>
    /// Presenting an access token to a protected resource. Range 1000-1099.
    /// </summary>
    public static class ProtectedResources
    {
        private const int Base = 1000;

        /// <summary>A token was attached to an outgoing request.</summary>
        public const int AccessTokenAttached = Base + 1;

        /// <summary>No token could be supplied for a request.</summary>
        public const int AccessTokenUnavailable = Base + 2;

        /// <summary>The resource server refused the token this client presented.</summary>
        public const int ResourceRefusedToken = Base + 3;

        /// <summary>The request ended at a different address than the one authorized.</summary>
        public const int AuthorizedUriChanged = Base + 4;
    }
}
