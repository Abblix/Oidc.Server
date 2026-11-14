// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios.HostIsolation;

/// <summary>A controller the host declares itself, which only the host isolation tests map.</summary>
[ApiController]
[Route(ItemsPath)]
public sealed class HostController : ControllerBase
{
    public const string ItemsPath = "/host/items";
    public const string CulturesPath = ItemsPath + "/cultures";
    public const string TextPath = ItemsPath + "/text";
    public const string RefusedPath = ItemsPath + "/refused";
    public const string Name = "host";

    [HttpPost]
    public HostItem Post(HostItem item) => item;

    [HttpGet]
    public HostItem Get() => new() { Name = Name };

    [HttpGet(CulturesPath)]
    public object Cultures([FromQuery] List<CultureInfo> languages, [FromQuery] int count)
        => new { languages = languages.Select(language => language.Name), count };

    [HttpGet(TextPath)]
    public string Text() => Name;

    [HttpGet(RefusedPath)]
    public IActionResult Refused() => Unauthorized();
}
