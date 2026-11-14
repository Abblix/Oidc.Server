// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>A host controller whose route carries no token.</summary>
[Route(Template)]
public sealed class HostPlainController : ControllerBase
{
    public const string Template = "plain/[controller]/items";

    [HttpGet]
    public IActionResult List() => Ok();
}
