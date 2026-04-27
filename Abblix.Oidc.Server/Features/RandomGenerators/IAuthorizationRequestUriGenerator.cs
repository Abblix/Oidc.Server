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

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Produces unique, unguessable request URIs used to reference stored authorization request objects,
/// such as those handled by Pushed Authorization Requests (RFC 9126) via the <c>request_uri</c> parameter.
/// Implementations must derive the URI from a high-entropy, cryptographically secure random value to prevent
/// an attacker from guessing or enumerating active authorization requests.
/// </summary>
public interface IAuthorizationRequestUriGenerator
{
    /// <summary>
    /// Generates a unique, unpredictable URI suitable for use as the <c>request_uri</c> reference for a
    /// previously stored authorization request.
    /// </summary>
    /// <returns>A unique URI that serves as the identifier for a specific authorization request.</returns>
    Uri GenerateRequestUri();
}
