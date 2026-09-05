// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>
/// Formats the framework-neutral OpenID Connect configuration metadata into an <see cref="IResult"/>, enriching it
/// with the absolute endpoint URLs resolved for the current request.
/// </summary>
/// <remarks>
/// This is the Minimal API counterpart of the MVC integration's <c>IConfigurationResponseFormatter</c>: same mapping
/// logic, but it returns an <see cref="IResult"/> instead of an <c>ActionResult</c>, and it resolves endpoint URLs
/// from the configured route templates plus the request's base URL rather than from controller/action descriptors.
/// </remarks>
public interface IConfigurationResponseFormatter
{
    /// <summary>
    /// Formats the configuration response, adding endpoint URLs and (when enabled) the RFC 8414 signed metadata.
    /// </summary>
    /// <param name="response">The framework-neutral configuration metadata produced by the core handler.</param>
    /// <returns>An <see cref="IResult"/> that writes the discovery document as JSON.</returns>
    Task<IResult> FormatResponseAsync(EndpointResponse response);
}
