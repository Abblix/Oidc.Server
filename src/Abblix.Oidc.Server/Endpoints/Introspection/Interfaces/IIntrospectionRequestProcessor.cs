// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Builds the RFC 7662 introspection response for an already-validated request: returns
/// <c>active=true</c> with claims for a live token, or <c>active=false</c> alone when the
/// token is missing, expired, revoked, or issued to a different client (section 2.2).
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
