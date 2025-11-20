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
/// Handles CIBA poll mode token retrieval at the token endpoint.
/// In poll mode, clients repeatedly poll until authentication completes.
/// Tokens are removed from storage immediately after retrieval.
/// </summary>
/// <param name="storage">Storage for backchannel authentication requests.</param>
public class PollModeGrantProcessor(IBackChannelAuthenticationStorage storage)
    : IBackChannelAuthenticationGrantProcessor
{
    // Poll mode clients are allowed to poll the token endpoint
    public OidcError? ValidateTokenEndpointAccess() => null;

    public async Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        // In poll mode, remove immediately after token retrieval per CIBA spec
        await storage.RemoveAsync(authenticationRequestId);

        return request.AuthorizedGrant;
    }
}
