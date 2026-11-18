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
    /// <summary>How many values the query and the form carry under <paramref name="name"/> together.</summary>
    public int Count(string name) => query[name].Count + (form?[name].Count ?? 0);

    public StringValues this[string name]
    {
        get
        {
            // A parameter that takes one value and arrives in both is refused through Count. For one that may
            // repeat, the form precedes the query, as the MVC composite value provider orders them
            // (FormValueProviderFactory before QueryStringValueProviderFactory), so both hosts read the same entries
            if (form is not null && form.TryGetValue(name, out var fromForm) && fromForm.Count > 0)
                return fromForm;

            if (query.TryGetValue(name, out var fromQuery))
                return fromQuery;

            return StringValues.Empty;
        }
    }
}
