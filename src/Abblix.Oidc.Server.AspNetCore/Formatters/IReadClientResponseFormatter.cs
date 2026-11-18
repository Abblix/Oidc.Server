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

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>Formats the result of reading a client configuration (RFC 7592) into a <typeparamref name="TResult"/>.</summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IReadClientResponseFormatter<TResult> where TResult : class
{
    /// <summary>Formats the read result (200 with the client configuration, or the OAuth error).</summary>
    Task<TResult> FormatResponseAsync(ClientRequest request, Result<ReadClientSuccessfulResponse, OidcError> response);
}
