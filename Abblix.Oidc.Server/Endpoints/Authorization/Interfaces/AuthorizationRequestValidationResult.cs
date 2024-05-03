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

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Serves as the base record for representing the result of an authorization request validation process.
/// It encapsulates the response mode that indicates how the authorization response should be delivered to the client,
/// providing a foundation for specific types of validation results, such as successful validations, errors
/// or other custom outcomes.
/// </summary>
/// <param name="ResponseMode">
/// The response mode to be used for delivering the authorization response, indicating whether the response
/// should be returned directly, via a redirection URI, or using other methods as defined
/// by the OAuth 2.0 specification and extensions.
/// </param>
public abstract record AuthorizationRequestValidationResult(string ResponseMode = ResponseModes.Query);
