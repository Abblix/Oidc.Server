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

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

partial class SecureHttpFetcher
{
    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.ResponseTooLarge,
        Level = LogLevel.Warning,
        Message = "Response from {Uri} exceeds maximum allowed size. Content-Length: {ContentLength} bytes, Max: {MaxSize} bytes")]
    private partial void LogResponseTooLarge(Sanitized Uri, long ContentLength, long MaxSize);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.UnexpectedContentType,
        Level = LogLevel.Warning,
        Message = "Response from {Uri} has unexpected Content-Type: {ContentType}, expected application/json")]
    private partial void LogUnexpectedContentType(Sanitized Uri, string ContentType);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.Timeout,
        Level = LogLevel.Warning,
        Message = "Timeout while fetching content from {Uri}")]
    private partial void LogTimeout(Exception ex, Sanitized Uri);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.SsrfProtectionBlocked,
        Level = LogLevel.Warning,
        Message = "SSRF protection blocked request to {Uri}")]
    private partial void LogSsrfProtectionBlocked(Exception ex, Sanitized Uri);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.FetchFailed,
        Level = LogLevel.Warning,
        Message = "Unable to fetch content from {Uri}")]
    private partial void LogFetchFailed(Exception ex, Sanitized Uri);
}
