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

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// A validation failure: the code a receiver branches on, and the sentence a log reader needs.
/// </summary>
/// <param name="Code">The failure class.</param>
/// <param name="Description">What exactly failed, in the words of the step that found it.</param>
public record SecurityEventTokenValidationError(SecurityEventTokenErrorCode Code, string Description)
{
    /// <summary>
    /// Returns the description - the half of the error a human reads.
    /// </summary>
    public override string ToString() => Description;
}
