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
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;

/// <summary>
/// Handles CIBA ping mode token retrieval at the token endpoint.
/// In ping mode, the server sends a notification to the client, then the client retrieves tokens.
/// Tokens remain in storage after retrieval (allows multiple retrievals after single notification).
/// </summary>
public class PingModeGrantProcessor : IBackChannelAuthenticationGrantProcessor
{
    // Ping mode clients are allowed to poll the token endpoint
    public OidcError? ValidateTokenEndpointAccess() => null;

    public Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        // In ping mode, keep tokens in storage (allows single notification, multiple retrievals)
        return Task.FromResult<Result<AuthorizedGrant, OidcError>>(request.AuthorizedGrant);
    }
}
