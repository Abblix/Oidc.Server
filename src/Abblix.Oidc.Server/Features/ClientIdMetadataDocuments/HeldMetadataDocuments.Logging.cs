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

partial class HeldMetadataDocuments
{
    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientIdMetadataDocuments.DocumentRefused,
        Level = LogLevel.Warning,
        Message = "The client metadata document of {ClientId} is refused: {Reason}")]
    private partial void LogDocumentRefused(Sanitized ClientId, Sanitized Reason);

    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientIdMetadataDocuments.HeldCopyServed,
        Level = LogLevel.Warning,
        Message = "The client metadata document of {ClientId} could not be fetched again, and the copy held is served: {Reason}")]
    private partial void LogHeldCopyServed(Sanitized ClientId, Sanitized Reason);
}
