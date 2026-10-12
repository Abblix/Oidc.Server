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


namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Thrown when the token endpoint refuses a request or cannot be reached.
/// </summary>
public sealed class TokenRequestException : Exception
{
    /// <summary>
    /// Creates the exception from what the provider returned.
    /// </summary>
    public TokenRequestException(string message, string? error = null, string? errorDescription = null)
        : base(message)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    /// <summary>
    /// Creates the exception for a failure that never reached a protocol answer.
    /// </summary>
    public TokenRequestException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// The error code the provider returned, or <c>null</c> when the request never got that far.
    /// </summary>
    /// <remarks>
    /// Carried separately from the message because callers act on it. A refresh answered with
    /// <see cref="TokenErrorCodes.InvalidGrant"/> means the token presented has been rotated away, which is
    /// recoverable by re-reading what is stored; every other code is not.
    /// </remarks>
    public string? Error { get; }

    /// <summary>
    /// The provider's elaboration on <see cref="Error"/>, when it gave one.
    /// </summary>
    public string? ErrorDescription { get; }
}
