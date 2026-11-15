// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// Formats the framework-neutral OpenID Connect configuration metadata into a <typeparamref name="TResult"/>, enriching it
/// with the absolute endpoint URLs resolved for the current request.
/// </summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
public interface IConfigurationResponseFormatter<TResult> where TResult : class
{
    /// <summary>
    /// Formats the configuration response, adding endpoint URLs and (when enabled) the RFC 8414 signed metadata.
    /// </summary>
    /// <param name="response">The framework-neutral configuration metadata produced by the core handler.</param>
    /// <returns>A <typeparamref name="TResult"/> that writes the discovery document as JSON.</returns>
    Task<TResult> FormatResponseAsync(EndpointResponse response);
}
