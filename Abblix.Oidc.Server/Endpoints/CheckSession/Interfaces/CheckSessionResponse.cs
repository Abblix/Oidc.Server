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

namespace Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;

/// <summary>
/// Represents the response to a check session request in OpenID Connect Session Management.
/// This record contains the necessary information to ascertain the current state of a user session.
/// </summary>
/// <param name="HtmlContent">The HTML content to be rendered, typically used in an iframe for session checking.</param>
/// <param name="CacheKey">An object that represents a cache key, used for optimizing session state checks.
/// It serves as a key for caching the response to reduce frequent reevaluation when the session state is expected
/// to remain unchanged for an extended period, enhancing performance.</param>
public record CheckSessionResponse(string HtmlContent, object CacheKey);
