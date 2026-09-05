// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the result of reading a client configuration (RFC 7592) into an <see cref="IResult"/>.</summary>
public interface IReadClientResponseFormatter
{
    /// <summary>Formats the read result (200 with the client configuration, or the OAuth error).</summary>
    Task<IResult> FormatResponseAsync(ClientRequest request, Result<ReadClientSuccessfulResponse, OidcError> response);
}
