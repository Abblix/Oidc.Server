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

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Defines the details of user consents required for specific scopes and resources.
/// This record is used to manage and validate user consent for accessing specific scopes and resources,
/// ensuring that consent is explicitly granted according to the requirements of the application and compliance
/// standards.
/// </summary>
/// <param name="Scopes">An array of <see cref="ScopeDefinition"/> that represents the scopes for which user consent
/// is needed.</param>
/// <param name="Resources">An array of <see cref="ResourceDefinition"/> that represents the resources for which
/// user consent is needed.</param>
public record ConsentDefinition(ScopeDefinition[] Scopes, ResourceDefinition[] Resources);
