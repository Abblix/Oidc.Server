// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.JwtBearer;

partial class JwtBearerIssuerProvider
{
	[LoggerMessage(
		EventId = LogEvents.Tokens.JwtBearerIssuerProvider.IssuerNotTrusted,
		Level = LogLevel.Debug,
		Message = "Issuer {Issuer} is not in the trusted issuers list")]
	private partial void LogIssuerNotTrusted(Sanitized Issuer);

	[LoggerMessage(
		EventId = LogEvents.Tokens.JwtBearerIssuerProvider.InvalidIssuerUri,
		Level = LogLevel.Debug,
		Message = "Invalid issuer URI format: {Issuer}")]
	private partial void LogInvalidIssuerUri(Sanitized Issuer);

	[LoggerMessage(
		EventId = LogEvents.Tokens.JwtBearerIssuerProvider.SigningKeysForUntrustedIssuer,
		Level = LogLevel.Warning,
		Message = "Attempted to get signing keys for untrusted issuer {Issuer}")]
	private partial void LogSigningKeysForUntrustedIssuer(Sanitized Issuer);
}
