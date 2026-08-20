// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

partial class SoftwareStatementValidator
{
    [LoggerMessage(
        EventId = LogEvents.DynamicClientManagement.SoftwareStatementValidator.ValidationFailed,
        Level = LogLevel.Warning,
        Message = "Software statement validation failed: {Error}")]
    private partial void LogValidationFailed(string Error);

    [LoggerMessage(
        EventId = LogEvents.DynamicClientManagement.SoftwareStatementValidator.IssuerNotTrusted,
        Level = LogLevel.Debug,
        Message = "Software statement issuer {Issuer} is not trusted")]
    private partial void LogIssuerNotTrusted(string Issuer);
}
