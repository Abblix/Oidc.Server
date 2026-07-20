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

namespace Abblix.Oidc.Client.Features.AuthorizationResponses;

/// <summary>
/// Thrown when an authorization response must not be acted on. The login it belongs to stops here.
/// </summary>
/// <remarks>
/// RFC 9207 section 2.4 states the consequence for the issuer case in full: a client that finds the
/// wrong issuer "MUST reject the authorization response and MUST NOT proceed with the authorization
/// grant". Throwing is how that second half is made unskippable - there is no result object a caller
/// can look past on the way to redeeming the code.
/// </remarks>
public sealed class AuthorizationResponseException : Exception
{
    /// <summary>
    /// Creates the exception describing why the response was refused.
    /// </summary>
    public AuthorizationResponseException(string message)
        : base(message)
    {
    }
}
