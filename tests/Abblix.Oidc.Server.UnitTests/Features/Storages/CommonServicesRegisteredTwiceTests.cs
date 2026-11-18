// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Consents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// The services every feature relies on, registered a second time, as a host calling the registration before the
/// server's own call does.
/// </summary>
public class CommonServicesRegisteredTwiceTests
{
    /// <summary>
    /// A server whose host chose no consent provider is refused once: a second registration does not add the check of
    /// that choice again.
    /// </summary>
    [Fact]
    public void AServerWithoutAConsentProvider_IsRefusedOnce()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCommonServices();
        services.AddCommonServices();
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<ConsentProviderChoice>>().Value);
        Assert.Single(refusal.Failures);
    }
}
