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

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class TlsClientAuthenticator
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.ClientNotFound,
        Level = LogLevel.Debug,
        Message = "mTLS auth failed: unknown client_id {ClientId}")]
    private partial void LogClientNotFound(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.NoMatchingPublicKey,
        Level = LogLevel.Warning,
        Message = "mTLS auth failed: no matching JWKS public key found for client_id {ClientId}")]
    private partial void LogNoMatchingPublicKey(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.Authenticated,
        Level = LogLevel.Information,
        Message = "mTLS client authenticated via self-signed certificate for client_id {ClientId}")]
    private partial void LogAuthenticated(string ClientId);
}
