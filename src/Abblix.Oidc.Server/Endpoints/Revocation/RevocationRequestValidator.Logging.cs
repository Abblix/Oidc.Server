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

namespace Abblix.Oidc.Server.Endpoints.Revocation;

partial class RevocationRequestValidator
{
	[LoggerMessage(
		EventId = LogEvents.Endpoints.RevocationRequestValidator.TokenIssuedToAnotherClient,
		Level = LogLevel.Warning,
		Message = "The token was issued to another client {ClientId}")]
	private partial void LogTokenIssuedToAnotherClient(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.RevocationRequestValidator.TokenValidationFailed,
		Level = LogLevel.Warning,
		Message = "The token validation failed: {@Error}")]
	private partial void LogTokenValidationFailed(JwtValidationError Error);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.RevocationRequestValidator.CallerRateLimited,
		Level = LogLevel.Warning,
		Message = "Revocation refused for client {ClientId}: it is over its budget of requests")]
	private partial void LogCallerRateLimited(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.RevocationRequestValidator.SourceRateLimited,
		Level = LogLevel.Warning,
		Message = "Revocation refused without reading a credential: the source is over its budget of failed client authentications")]
	private partial void LogSourceRateLimited();
}
