// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Reads request values from the query string and (when present) the posted form, mirroring the MVC
/// <c>[FromQueryOrForm]</c> binding source so the authorization request binds from a GET query or a POST form.
/// </summary>
internal readonly struct RequestValues(IQueryCollection query, IFormCollection? form)
{
    public StringValues this[string name]
    {
        get
        {
            // Form precedes query on a duplicate key, mirroring the MVC composite value provider order
            // (FormValueProviderFactory before QueryStringValueProviderFactory). Keeps the two adapters from
            // authorizing different requests under query/body parameter pollution.
            if (form is not null && form.TryGetValue(name, out var fromForm) && fromForm.Count > 0)
                return fromForm;

            if (query.TryGetValue(name, out var fromQuery))
                return fromQuery;

            return StringValues.Empty;
        }
    }
}
