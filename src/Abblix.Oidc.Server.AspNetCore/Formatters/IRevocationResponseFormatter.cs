// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Utils;
using RevocationRequest = Abblix.Oidc.Server.Model.RevocationRequest;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>Formats the result of a token revocation request into a <typeparamref name="TResult"/>.</summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IRevocationResponseFormatter<TResult> where TResult : class
{
    /// <summary>Formats the revocation result (empty 200 on success, OAuth error otherwise).</summary>
    Task<TResult> FormatResponseAsync(RevocationRequest request, Result<TokenRevoked, OidcError> response);
}
