// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;

/// <summary>
/// Handles CIBA push mode token retrieval validation at the token endpoint.
/// In push mode, tokens are delivered directly to the client's notification endpoint.
/// Push mode clients should NEVER poll the token endpoint - this is an error.
/// </summary>
public class PushModeGrantProcessor : IBackChannelGrantProcessor
{
    /// <summary>
    /// Push mode delivers tokens directly to the client's notification endpoint, so any call to the
    /// token endpoint with a push-mode <c>auth_req_id</c> is a protocol error and is rejected with
    /// <c>invalid_grant</c>.
    /// </summary>
    public OidcError ValidateTokenEndpointAccess() => new(
        ErrorCodes.InvalidGrant,
        "Push mode clients receive tokens via push delivery and must not poll the token endpoint");

    /// <summary>
    /// Defensive fallback that returns <c>invalid_grant</c>. In practice this method is unreachable
    /// because <see cref="ValidateTokenEndpointAccess"/> short-circuits push-mode token-endpoint requests.
    /// </summary>
    public Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        return Task.FromResult<Result<AuthorizedGrant, OidcError>>(
            new OidcError(
                ErrorCodes.InvalidGrant,
                "Push mode clients receive tokens via push delivery and must not poll the token endpoint"));
    }
}
