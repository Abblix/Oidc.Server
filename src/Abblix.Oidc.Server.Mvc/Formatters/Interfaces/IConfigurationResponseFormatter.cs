// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using ModelResponse = Abblix.Oidc.Server.Model.ConfigurationResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines the contract for formatting OpenID Connect configuration responses
/// by mapping metadata and enriching with MVC-specific information such as endpoint URLs.
/// </summary>
public interface IConfigurationResponseFormatter
{
	/// <summary>
	/// Formats the configuration response by mapping metadata and adding endpoint URLs.
	/// </summary>
	/// <param name="response">Framework-agnostic configuration response with metadata.</param>
	/// <returns>An action result with the MVC-enriched configuration response including URLs.</returns>
	Task<ActionResult<ModelResponse>> FormatResponseAsync(EndpointResponse response);
}
