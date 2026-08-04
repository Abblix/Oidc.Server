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
