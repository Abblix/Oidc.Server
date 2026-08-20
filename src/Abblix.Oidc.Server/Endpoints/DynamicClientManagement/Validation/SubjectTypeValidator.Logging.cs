// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

partial class SubjectTypeValidator
{
    [LoggerMessage(
        EventId = LogEvents.DynamicClientManagement.SubjectTypeValidator.SectorIdentifierMissingUris,
        Level = LogLevel.Warning,
        Message = "The following registered redirect URIs are missing from the document at {SectorIdentifierUri}: {@MissingUris}")]
    private partial void LogSectorIdentifierMissingUris(Sanitized SectorIdentifierUri, Uri[] MissingUris);
}
