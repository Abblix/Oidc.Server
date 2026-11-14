// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Redirects the user agent with HTTP 303 See Other, as <see cref="HttpResponseExtensions.RedirectSeeOther"/>
/// explains.
/// </summary>
internal sealed class SeeOtherResult : ActionResult
{
    private readonly string _location;

    /// <summary>
    /// Initializes a new instance of the <see cref="SeeOtherResult"/> class.
    /// </summary>
    /// <param name="location">The absolute URI to redirect the user agent to.</param>
    public SeeOtherResult(string location) => _location = location;

    /// <inheritdoc />
    public override void ExecuteResult(ActionContext context)
        => context.HttpContext.Response.RedirectSeeOther(_location);
}
