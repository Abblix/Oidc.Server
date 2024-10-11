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

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents an error response in the backchannel authentication process.
/// This record encapsulates details about the error, including an error code and a human-readable
/// description of what went wrong. It is returned when the authentication request fails due to various
/// reasons such as invalid parameters, unauthorized access, or other validation issues.
/// </summary>
/// <param name="Error">The error code that identifies the type of error encountered during the backchannel
/// authentication process.</param>
/// <param name="ErrorDescription">A human-readable description providing more details about the error.</param>
public record BackChannelAuthenticationError(string Error, string ErrorDescription)
    : BackChannelAuthenticationResponse;
