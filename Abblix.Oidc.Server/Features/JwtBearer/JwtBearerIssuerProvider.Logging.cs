// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.JwtBearer;

partial class JwtBearerIssuerProvider
{
	[LoggerMessage(
		EventId = LogEvents.Tokens.JwtBearerIssuerProvider.IssuerNotTrusted,
		Level = LogLevel.Debug,
		Message = "Issuer {Issuer} is not in the trusted issuers list")]
	private partial void LogIssuerNotTrusted(string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Tokens.JwtBearerIssuerProvider.InvalidIssuerUri,
		Level = LogLevel.Debug,
		Message = "Invalid issuer URI format: {Issuer}")]
	private partial void LogInvalidIssuerUri(string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Tokens.JwtBearerIssuerProvider.SigningKeysForUntrustedIssuer,
		Level = LogLevel.Warning,
		Message = "Attempted to get signing keys for untrusted issuer {Issuer}")]
	private partial void LogSigningKeysForUntrustedIssuer(string Issuer);
}
