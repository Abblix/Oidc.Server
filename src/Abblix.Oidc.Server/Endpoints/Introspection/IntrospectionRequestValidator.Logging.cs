// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Introspection;

partial class IntrospectionRequestValidator
{
	[LoggerMessage(
		EventId = LogEvents.Endpoints.IntrospectionRequestValidator.InvalidJwt,
		Level = LogLevel.Warning,
		Message = "The incoming JWT token is invalid: {@JwtValidationError}")]
	private partial void LogInvalidJwt(JwtValidationError JwtValidationError);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.IntrospectionRequestValidator.PublicClientRejected,
		Level = LogLevel.Warning,
		Message = "Introspection rejected for public client {ClientId}: 'none' authentication does not satisfy RFC 7662 section 2.1")]
	private partial void LogPublicClientRejected(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.IntrospectionRequestValidator.CallerRateLimited,
		Level = LogLevel.Warning,
		Message = "Introspection refused for client {ClientId}: it is over its budget of requests")]
	private partial void LogCallerRateLimited(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.IntrospectionRequestValidator.SourceRateLimited,
		Level = LogLevel.Warning,
		Message = "Introspection refused without reading a credential: the source is over its budget of failed client authentications")]
	private partial void LogSourceRateLimited();
}
