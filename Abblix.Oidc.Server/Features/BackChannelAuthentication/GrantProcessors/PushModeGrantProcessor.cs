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
    // Push mode clients should never poll the token endpoint
    public OidcError ValidateTokenEndpointAccess() => new(
        ErrorCodes.InvalidGrant,
        "Push mode clients receive tokens via push delivery and must not poll the token endpoint");

    public Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        // This should never be reached since ValidateTokenEndpointAccess() always returns an error for push mode
        return Task.FromResult<Result<AuthorizedGrant, OidcError>>(
            new OidcError(
                ErrorCodes.InvalidGrant,
                "Push mode clients receive tokens via push delivery and must not poll the token endpoint"));
    }
}
