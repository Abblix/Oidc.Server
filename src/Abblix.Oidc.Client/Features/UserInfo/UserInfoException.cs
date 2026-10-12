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

namespace Abblix.Oidc.Client.Features.UserInfo;

/// <summary>
/// Thrown when the UserInfo claims could not be obtained, or arrived describing somebody else.
/// </summary>
public sealed class UserInfoException : Exception
{
    /// <summary>
    /// Creates the exception describing why the claims were refused or could not be read.
    /// </summary>
    public UserInfoException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Creates the exception for a failure that never reached a protocol answer, such as the endpoint
    /// being unreachable.
    /// </summary>
    public UserInfoException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
