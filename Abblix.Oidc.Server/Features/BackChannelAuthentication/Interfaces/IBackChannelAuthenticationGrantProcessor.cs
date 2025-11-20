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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines mode-specific processing logic for handling authenticated CIBA requests at the token endpoint.
/// Different delivery modes (poll, ping, push) have different requirements for token retrieval.
/// </summary>
public interface IBackChannelAuthenticationGrantProcessor
{
    /// <summary>
    /// Validates that a token request is allowed for this delivery mode.
    /// For example, push mode clients should never poll the token endpoint.
    /// </summary>
    /// <returns>
    /// Null if the request is valid for this mode, or an error if the client
    /// is attempting an operation not allowed by their delivery mode.
    /// </returns>
    OidcError? ValidateTokenEndpointAccess();

    /// <summary>
    /// Validates whether the client is allowed to retrieve tokens via the token endpoint for this delivery mode,
    /// and performs any mode-specific post-retrieval actions (e.g., removing from storage).
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated CIBA request from storage.</param>
    /// <returns>
    /// Either the authorized grant if retrieval is allowed and successful, or an error indicating
    /// why token retrieval is not permitted for this mode.
    /// </returns>
    Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request);
}
