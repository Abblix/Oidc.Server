// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
