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

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

partial class SecureHttpFetcherExtensions
{
	[LoggerMessage(
		EventId = LogEvents.HttpFetch.SecureHttpFetcherExtensions.FetchingJwks,
		Level = LogLevel.Debug,
		Message = "Fetching JWKS for {EntityType} {EntityId} from {JwksUri}")]
	private static partial void LogFetchingJwks(ILogger logger, string EntityType, string EntityId, Uri JwksUri);

	[LoggerMessage(
		EventId = LogEvents.HttpFetch.SecureHttpFetcherExtensions.JwksEmpty,
		Level = LogLevel.Warning,
		Message = "JWKS for {EntityType} {EntityId} from {JwksUri} is empty or invalid")]
	private static partial void LogJwksEmpty(ILogger logger, string EntityType, string EntityId, Uri JwksUri);

	[LoggerMessage(
		EventId = LogEvents.HttpFetch.SecureHttpFetcherExtensions.JwksFetchFailed,
		Level = LogLevel.Error,
		Message = "Failed to fetch JWKS for {EntityType} {EntityId} from {JwksUri}: {Error}")]
	private static partial void LogJwksFetchFailed(ILogger logger, string EntityType, string EntityId, Uri JwksUri, string? Error);
}
