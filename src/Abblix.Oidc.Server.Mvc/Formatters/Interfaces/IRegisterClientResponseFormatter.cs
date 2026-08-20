// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting client registration responses.
/// </summary>
public interface IRegisterClientResponseFormatter
{
    /// <summary>
    /// Formats the given client registration response asynchronously.
    /// </summary>
    /// <param name="request">The original client registration request.</param>
    /// <param name="response">The client registration response to format.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.
    /// The task result contains the formatted <see cref="ActionResult"/>.</returns>
    Task<ActionResult> FormatResponseAsync(ClientRegistrationRequest request, Result<ClientRegistrationSuccessResponse, OidcError> response);
}
