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
}
