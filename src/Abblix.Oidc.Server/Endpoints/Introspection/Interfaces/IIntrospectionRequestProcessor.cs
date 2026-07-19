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
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Builds the RFC 7662 introspection response for an already-validated request: returns
/// <c>active=true</c> with claims for a live token, or <c>active=false</c> alone when the
/// token is missing, expired, revoked, or issued to a different client (§2.2).
/// </summary>
public interface IIntrospectionRequestProcessor
{
	/// <summary>
	/// Produces the introspection response for a validated request.
	/// </summary>
	/// <param name="request">A request that has cleared client authentication and token validation.</param>
	/// <returns>An <see cref="IntrospectionSuccess"/>; processing-time errors map to <see cref="OidcError"/>.</returns>
	Task<Result<IntrospectionSuccess, OidcError>> ProcessAsync(ValidIntrospectionRequest request);
}
