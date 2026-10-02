// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

partial class JwtBearerAudienceValidator
{
	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AudienceFailedStrict,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: audience validation failed. Expected {TokenEndpoint}, got {Audiences}")]
	private partial void LogAudienceFailedStrict(Uri TokenEndpoint, string Audiences);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AudienceFailedPermissive,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: audience validation failed. Expected {TokenEndpoint} or {ApplicationUri}, got {Audiences}")]
	private partial void LogAudienceFailedPermissive(Uri TokenEndpoint, string ApplicationUri, string Audiences);
}
