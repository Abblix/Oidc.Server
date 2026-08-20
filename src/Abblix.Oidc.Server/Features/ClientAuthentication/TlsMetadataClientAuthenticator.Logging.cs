// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class TlsMetadataClientAuthenticator
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsMetadataClientAuthenticator.NoTlsMetadataConfigured,
        Level = LogLevel.Warning,
        Message = "tls_client_auth: client {ClientId} has no tls metadata configured")]
    private partial void LogNoTlsMetadataConfigured(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsMetadataClientAuthenticator.Authenticated,
        Level = LogLevel.Information,
        Message = "tls_client_auth: client authenticated: {ClientId}")]
    private partial void LogAuthenticated(string ClientId);
}
