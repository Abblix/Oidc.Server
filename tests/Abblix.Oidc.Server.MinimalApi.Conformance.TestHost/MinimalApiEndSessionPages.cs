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

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>The host's logout pages as the Minimal API adapter's results.</summary>
public sealed class MinimalApiEndSessionPages(
    IEndSessionResponseFormatter<IResult> inner,
    IOidcEndpointResolver endpointResolver) : EndSessionPages<IResult>(inner, endpointResolver)
{
    protected override IResult Html(string content) => Results.Content(content, "text/html");
}
