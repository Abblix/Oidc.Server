// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Authenticates the calling client (RFC 7662 section 2.1, "the protected resource calls the
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
