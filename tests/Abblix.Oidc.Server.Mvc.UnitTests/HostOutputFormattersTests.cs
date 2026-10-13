// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// The output formatters are the host's: a host that took one away does not get it back from the package.
/// </summary>
public class HostOutputFormattersTests
{
    [Fact]
    public void AFormatterTheHostRemovedStaysRemoved()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddControllers(options => options.OutputFormatters.RemoveType<StringOutputFormatter>());
        services.AddOidcMvc();

        var formatters = services.BuildServiceProvider().GetRequiredService<IOptions<MvcOptions>>().Value.OutputFormatters;

        Assert.DoesNotContain(formatters, formatter => formatter is StringOutputFormatter);
    }
}
