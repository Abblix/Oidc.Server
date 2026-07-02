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
