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

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class ClientSecretAuthenticator
{
	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.ClientNotFound,
		Level = LogLevel.Debug,
		Message = "Client authentication failed: client information for id {ClientId} is missing")]
	private partial void LogClientNotFound(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.WrongAuthMethod,
		Level = LogLevel.Debug,
		Message = "Client authentication failed: client {ClientId} uses another authentication method")]
	private partial void LogWrongAuthMethod(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.NoSecretsConfigured,
		Level = LogLevel.Debug,
		Message = "Client authentication failed: no secrets are configured for client {ClientId}")]
	private partial void LogNoSecretsConfigured(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.NoMatchingSecret,
		Level = LogLevel.Warning,
		Message = "Client authentication failed: No matching secret found for client {ClientId}")]
	private partial void LogNoMatchingSecret(string ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.SecretExpired,
		Level = LogLevel.Warning,
		Message = "Client authentication failed: Secret has expired for client {ClientId}")]
	private partial void LogSecretExpired(string ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.Authenticated,
		Level = LogLevel.Information,
		Message = "Client authenticated successfully with client ID {ClientId}")]
	private partial void LogAuthenticated(string ClientId);
}
