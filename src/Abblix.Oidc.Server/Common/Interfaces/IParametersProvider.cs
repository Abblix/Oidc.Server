// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Extracts a flat set of name/value pairs from a response object - the reverse of binding - for delivery as query,
/// fragment or form_post parameters. The transport adapters (MVC, Minimal API) share this contract because flattening
/// a response DTO is framework-neutral; the implementation lives in the core for the same reason.
/// </summary>
public interface IParametersProvider
{
    /// <summary>Retrieves the parameters as name/value pairs from the specified object.</summary>
    /// <param name="obj">The object to extract parameters from.</param>
    /// <returns>The parameter name/value pairs.</returns>
    IEnumerable<(string name, string? value)> GetParameters(object obj);
}
