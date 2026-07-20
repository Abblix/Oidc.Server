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

namespace Abblix.Oidc.Client.Features.SigningKeys;

/// <summary>
/// Thrown when the OpenID Provider's signing keys cannot be obtained.
/// </summary>
/// <remarks>
/// Distinct from a signature that simply fails to verify: this says the client never got the keys to check
/// against, which is an operational fault rather than a rejected token.
/// </remarks>
public sealed class SigningKeysException : Exception
{
    /// <summary>
    /// Creates the exception with a message describing what about the key set failed.
    /// </summary>
    public SigningKeysException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Creates the exception with a message and the underlying transport or parsing failure.
    /// </summary>
    public SigningKeysException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
