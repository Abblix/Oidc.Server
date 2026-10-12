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


namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// Thrown when no access token can be supplied for a request.
/// </summary>
/// <remarks>
/// Separate from <see cref="AccessTokenPresentationException"/> on purpose: this one says the caller has no
/// credential to offer, which a host may answer by signing the user in again, while the other says the
/// request itself was one this client will not send, which a host answers by fixing its configuration.
/// </remarks>
public sealed class AccessTokenUnavailableException : Exception
{
    /// <summary>
    /// Creates the exception.
    /// </summary>
    public AccessTokenUnavailableException(AccessTokenUnavailableReason reason, string message)
        : base(message)
        => Reason = reason;

    /// <summary>
    /// Creates the exception for a failure that carries an underlying one.
    /// </summary>
    public AccessTokenUnavailableException(
        AccessTokenUnavailableReason reason, string message, Exception innerException)
        : base(message, innerException)
        => Reason = reason;

    /// <summary>
    /// Which of the three causes it was.
    /// </summary>
    public AccessTokenUnavailableReason Reason { get; }
}
