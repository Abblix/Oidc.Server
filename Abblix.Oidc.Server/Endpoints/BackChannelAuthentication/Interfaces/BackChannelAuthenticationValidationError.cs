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

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;

/// <summary>
/// Represents a validation error that occurs during the backchannel authentication request validation process.
/// This record encapsulates the error details, including an error code and a human-readable description
/// of the issue that caused the validation to fail.
/// </summary>
/// <param name="Error">A code representing the specific error that occurred during validation.</param>
/// <param name="ErrorDescription">A human-readable description providing more details about the validation error.
/// </param>
public record BackChannelAuthenticationValidationError(string Error, string ErrorDescription)
	: BackChannelAuthenticationValidationResult;
