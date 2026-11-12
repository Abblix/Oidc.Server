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

namespace Abblix.Oidc.Client.Features.IdentityTokens;

/// <summary>
/// Thrown when an ID Token fails validation. The login it belongs to must not proceed.
/// </summary>
/// <remarks>
/// There is deliberately no way to ask which check failed, and no partial result. Every rejection
/// here means the same thing to a caller - do not sign this user in - and a caller that could tell
/// "the nonce did not match" from "the signature did not verify" would be tempted to treat one as
/// recoverable. Neither is. The distinction lives in the message, for the operator reading a log.
/// </remarks>
public sealed class IdentityTokenValidationException : Exception
{
    /// <summary>
    /// Creates the exception describing why the token was refused.
    /// </summary>
    public IdentityTokenValidationException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Creates the exception for a failure that prevented the check from reaching a verdict, such as
    /// the provider's key set being unreachable.
    /// </summary>
    public IdentityTokenValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
