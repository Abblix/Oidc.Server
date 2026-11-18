// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

partial class ClientIdMetadataDocumentClients
{
    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientIdMetadataDocuments.IdentifierNotFetched,
        Level = LogLevel.Warning,
        Message = "The client identifier {ClientId} is not a client identifier URL this server fetches: {Reason}")]
    private partial void LogIdentifierNotFetched(Sanitized ClientId, string Reason);

    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientIdMetadataDocuments.IdentifierNotAllowed,
        Level = LogLevel.Warning,
        Message = "The client identifier URL {ClientId} starts with none of the prefixes this server fetches from")]
    private partial void LogIdentifierNotAllowed(Sanitized ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientIdMetadataDocuments.IdentifierNamesAServer,
        Level = LogLevel.Warning,
        Message = "The client identifier URL {ClientId} is the identifier of a server tenant {TenantId} issues for or trusts")]
    private partial void LogIdentifierNamesAServer(Sanitized ClientId, string TenantId);

    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientIdMetadataDocuments.ClientRefused,
        Level = LogLevel.Warning,
        Message = "The client metadata document of {ClientId} is refused at tenant {TenantId}: {Reason}")]
    private partial void LogClientRefused(Sanitized ClientId, string TenantId, Sanitized Reason);
}
