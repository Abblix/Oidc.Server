// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

partial class JwtBearerAudienceValidator
{
	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AudienceFailedStrict,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: audience validation failed. Expected {Issuer} or the token endpoint as one of [{TokenEndpoints}], got {Audiences}")]
	private partial void LogAudienceFailedStrict(string TokenEndpoints, string Issuer, Sanitized[] Audiences);

	// The same refusal under the event a host setting the permissive policy has its alerts keyed on
	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AudienceFailedPermissive,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: audience validation failed. Expected {Issuer} or the token endpoint as one of [{TokenEndpoints}], got {Audiences}")]
	private partial void LogAudienceFailedPermissive(string TokenEndpoints, string Issuer, Sanitized[] Audiences);
}
