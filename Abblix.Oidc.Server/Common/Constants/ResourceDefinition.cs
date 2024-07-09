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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Represents a resource with associated scopes, defining the permissions and access levels within an application.
/// This record is typically used to configure and enforce authorization policies based on resource identifiers
/// and their corresponding scopes.
/// </summary>
/// <param name="Resource">The identifier for the resource, often a unique name or URL representing the resource.</param>
/// <param name="Scopes">A variable number of scope definitions associated with the resource. Each scope definition
/// specifies a scope and its related claims, detailing the access levels and permissions granted.</param>
public record ResourceDefinition(Uri Resource, params ScopeDefinition[] Scopes);
