// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Locks the property that makes the live editing cursor work: the composite factory reads its members via
/// <c>GetKeyedServices</c> at resolve time, so a member added to the collection AFTER composition - with no
/// recompose - is picked up when the composite is resolved. Which registrations count as members is the
/// cursor's to decide, and only the cursor can produce one.
/// </summary>
public class LiveCompositionTests
{
    [Fact]
    public void MemberAddedAfterCompose_IsVisibleToCompositeAtResolve()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();

        services.Decompose<IPipelineStep>()
            .AddLast(ServiceDescriptor.Singleton<IPipelineStep, StepC>());

        using var provider = services.BuildServiceProvider();

        Assert.Equal("A,B,C", provider.GetRequiredService<IPipelineStep>().Name);
    }

    [Fact]
    public void AKeyedRegistrationCannotPassItselfOffAsAMember()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();

        // The composite type used to be the member key, so this registration joined the family. A member is
        // keyed by something only the composition machinery can build now, which is what keeps a host's own
        // keyed registrations - by name, by type, by anything - its own business.
        services.AddKeyedSingleton<IPipelineStep, StepC>(typeof(PipelineComposite));

        using var provider = services.BuildServiceProvider();

        Assert.Equal("A,B", provider.GetRequiredService<IPipelineStep>().Name);
        Assert.IsType<StepC>(provider.GetRequiredKeyedService<IPipelineStep>(typeof(PipelineComposite)));
    }
}
