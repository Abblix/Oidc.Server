// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines mode-specific processing logic for handling authenticated CIBA requests at the token endpoint.
/// Different delivery modes (poll, ping, push) have different requirements for token retrieval.
/// </summary>
public interface IBackChannelGrantProcessor
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
