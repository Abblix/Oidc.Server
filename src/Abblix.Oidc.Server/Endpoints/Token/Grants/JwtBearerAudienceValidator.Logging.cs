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
	// One event for every refusal, under the id the strict policy logged it with (AudienceFailedStrict), which existing
	// alerts are keyed on; the permissive policy's id is no longer logged
	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AudienceFailedStrict,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: audience validation failed. Expected {Issuer} or the token endpoint as one of [{TokenEndpoint}], got {Audiences}")]
	private partial void LogAudienceFailed(string TokenEndpoint, string Issuer, Sanitized[] Audiences);
}
