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

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Locks the property that makes the live editing cursor work: the composite factory reads its members via
/// <c>GetKeyedServices</c> at resolve time, so a keyed member added to the collection AFTER composition — with
/// no recompose — is picked up when the composite is resolved. The <see cref="IComposition{TInterface}"/> cursor
/// edits exactly those keyed descriptors, so its edits are live by the same mechanism.
/// </summary>
public class LiveCompositionTests
{
    [Fact]
    public void KeyedMemberAddedAfterCompose_IsVisibleToCompositeAtResolve()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();

        // For a plain family the member key IS the composite type. Registering another keyed member under it,
        // after Compose, is what the live cursor's AddLast does internally.
        services.AddKeyedSingleton<IPipelineStep, StepC>(typeof(PipelineComposite));

        using var provider = services.BuildServiceProvider();

        Assert.Equal("A,B,C", provider.GetRequiredService<IPipelineStep>().Name);
    }
}
