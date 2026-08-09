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

using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Locks the resolve-time half of the family API: a caller asks what a family holds and gets the members the
/// container will run, without saying - or knowing - whether the family was composed and under which key.
/// </summary>
public class ResolvedFamilyTests
{
    private const string EmailKey = "email";

    [Fact]
    public void Decompose_ReturnsTheMembersOfAComposedFamily()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();

        using var provider = services.BuildServiceProvider();

        // The composite hides its members from plain resolution, so this is the only way to see them.
        Assert.Equal(["A", "B"], provider.Decompose<IPipelineStep>().Select(step => step.Name));
        Assert.IsType<PipelineComposite>(provider.GetRequiredService<IPipelineStep>());
    }

    [Fact]
    public void Decompose_ReturnsTheMembersOfAFamilyThatWasNeverComposed()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();

        using var provider = services.BuildServiceProvider();

        // Same question, same answer: which arrangement the family is in is not the caller's business.
        Assert.Equal(["A", "B"], provider.Decompose<IPipelineStep>().Select(step => step.Name));
    }

    [Fact]
    public void Decompose_ReturnsTheMembersOfAKeyedFamily()
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<IPipelineStep, StepA>(EmailKey);
        services.AddKeyedSingleton<IPipelineStep, StepB>(EmailKey);
        services.ComposeKeyed<IPipelineStep, PipelineComposite>(EmailKey);

        using var provider = services.BuildServiceProvider();

        Assert.Equal(["A", "B"], provider.Decompose<IPipelineStep>(EmailKey).Select(step => step.Name));
    }

    [Fact]
    public void Decompose_RefusesAFamilyWithNoMembers()
    {
        var services = new ServiceCollection();

        using var provider = services.BuildServiceProvider();

        // The defect this refusal exists for: an empty answer is what a caller reading members by a key of its
        // own gets when the key is out of date, and a consumer that judges a pipeline reads that as every step
        // being absent. Silence would turn a question into a false report.
        var exception = Assert.Throws<InvalidOperationException>(() => provider.Decompose<IPipelineStep>());
        Assert.Contains(nameof(IPipelineStep), exception.Message);
    }

    [Fact]
    public void Decompose_RefusesAKeyedFamilyWithNoMembers_NamingTheKey()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(
            () => provider.Decompose<IPipelineStep>(EmailKey));

        Assert.Contains(EmailKey, exception.Message);
    }

    [Fact]
    public void Decompose_SeesAMemberTheCursorAddedAfterComposition()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPipelineStep, StepA>();
        services.AddSingleton<IPipelineStep, StepB>();
        services.Compose<IPipelineStep, PipelineComposite>();
        services.Decompose<IPipelineStep>().AddLast(ServiceDescriptor.Singleton<IPipelineStep, StepC>());

        using var provider = services.BuildServiceProvider();

        Assert.Equal(["A", "B", "C"], provider.Decompose<IPipelineStep>().Select(step => step.Name));
    }
}
