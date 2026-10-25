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


namespace Abblix.Oidc.Client.Features.SessionManagement;

/// <summary>
/// Builds the page this application serves as its session-watching frame
/// (OpenID Connect Session Management 1.0 section 3.1).
/// </summary>
public interface ISessionCheckFrameBuilder
{
    /// <summary>
    /// Builds the frame for a signed-in session.
    /// </summary>
    /// <param name="check">The provider's frame, this client's identifier and the login state.</param>
    /// <param name="selfOrigin">
    /// This application's own origin, which the frame addresses its verdict to. Passed in rather than
    /// configured, because it is a property of the request the page is being served for.
    /// </param>
    /// <returns>The document and the policy it must be served under.</returns>
    /// <exception cref="SessionCheckException">The provider's frame address is unusable.</exception>
    SessionCheckFrame Build(SessionCheck check, Uri selfOrigin);
}
