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

using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Defines the contract for a token context validator, responsible for validating different aspects of a token request
/// within a given context. Implementations of this interface ensure that the token request adheres to
/// the expected security and business rules.
/// </summary>
public interface ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the token request within the provided context, checking for compliance with
    /// the necessary validation rules such as client authentication, scope validation, grant validation, etc.
    /// </summary>
    /// <param name="context">The context containing the token request and related information that needs to be validated.</param>
    /// <returns>
    /// A <see cref="OidcError"/> containing error details if the validation fails;
    /// otherwise, returns null indicating that the validation was successful.
    /// </returns>
    Task<OidcError?> ValidateAsync(TokenValidationContext context);
}
