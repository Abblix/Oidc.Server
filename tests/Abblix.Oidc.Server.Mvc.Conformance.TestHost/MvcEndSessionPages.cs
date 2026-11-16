// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Conformance.TestHost;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Conformance.TestHost;

/// <summary>The host's logout pages as the MVC adapter's results.</summary>
public sealed class MvcEndSessionPages(
    IEndSessionResponseFormatter<ActionResult> inner,
    IOidcEndpointResolver endpointResolver) : EndSessionPages<ActionResult>(inner, endpointResolver)
{
    protected override ActionResult Html(string content) => new ContentResult
    {
        Content = content,
        ContentType = "text/html",
    };
}
