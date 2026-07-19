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

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Authenticates the calling client (RFC 7662 §2.1, "the protected resource calls the
/// introspection endpoint using an HTTP request") and validates the supplied <c>token</c>.
/// Implementations are expected to coerce token problems (expired, signed by a different
/// issuer, audience mismatch, issued to another client) into a non-disclosing
/// <c>active=false</c> result via <see cref="ValidIntrospectionRequest.InvalidToken"/>.
/// </summary>
public interface IIntrospectionRequestValidator
{
	/// <summary>
	/// Authenticates the caller and validates the introspected token.
	/// </summary>
	/// <param name="introspectionRequest">Wire-level request carrying the <c>token</c> to introspect.</param>
	/// <param name="clientRequest">Carrier of the client's authentication credentials.</param>
	/// <returns>
	/// A <see cref="ValidIntrospectionRequest"/> on success (with <c>Token</c> set or null);
	/// an <see cref="OidcError"/> only when the caller itself cannot be authenticated.
	/// </returns>
	Task<Result<ValidIntrospectionRequest, OidcError>> ValidateAsync(
		IntrospectionRequest introspectionRequest,
		ClientRequest clientRequest);
}
