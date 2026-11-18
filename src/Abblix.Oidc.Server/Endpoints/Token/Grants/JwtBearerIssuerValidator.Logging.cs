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

partial class JwtBearerIssuerValidator
{
	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.IssuerIsServedTenant,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: issuer {Issuer} is a tenant this server serves")]
	private partial void LogIssuerIsServedTenant(Sanitized Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.IssuerNotTrusted,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: issuer {Issuer} is not trusted")]
	private partial void LogIssuerNotTrusted(Sanitized Issuer);
}
