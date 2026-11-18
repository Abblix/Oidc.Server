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

partial class ClientIdMetadataDocumentFetcher
{
    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientIdMetadataDocuments.FetchFailed,
        Level = LogLevel.Warning,
        Message = "The client metadata document at {Url} could not be had (transient: {Transient}): {Reason}")]
    private partial void LogFetchFailed(Sanitized Url, bool Transient, Sanitized Reason);
}
