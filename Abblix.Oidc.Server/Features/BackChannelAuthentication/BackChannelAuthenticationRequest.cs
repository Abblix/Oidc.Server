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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Represents a backchannel authentication request in the context of Client-Initiated Backchannel Authentication
/// (CIBA), which is used to authenticate users without requiring direct interaction with their device at the time
/// of authentication.
/// </summary>
public record BackChannelAuthenticationRequest(AuthorizedGrant AuthorizedGrant)
{
    /// <summary>
    /// Holds the current status of the backchannel authentication request.
    /// This property tracks the lifecycle of the authentication process, indicating whether it is pending, completed,
    /// or encountered an error. Managing the status is crucial to properly handling polling or notification mechanisms
    /// as clients await a response to the backchannel authentication request.
    /// </summary>
    public BackChannelAuthenticationStatus Status { get; init; } = BackChannelAuthenticationStatus.Pending;

    /// <summary>
    /// Represents the grant that has been authorized as a result of the backchannel authentication request.
    /// Once the user has been successfully authenticated and the request validated, this property contains the
    /// necessary data to issue tokens. It encapsulates information about the authenticated session, including
    /// permissions and resources that the client is granted access to. This is a key element for securely
    /// issuing access and ID tokens following the completion of the backchannel authentication process.
    /// </summary>
    public AuthorizedGrant AuthorizedGrant { get; init; } = AuthorizedGrant;
}
