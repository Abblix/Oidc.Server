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
