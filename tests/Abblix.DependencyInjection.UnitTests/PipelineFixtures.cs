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

using System.Linq;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>Shared pipeline fixtures for the composed-family tests.</summary>
internal interface IPipelineStep
{
    string Name { get; }
}

internal sealed class StepA : IPipelineStep { public string Name => "A"; }
internal sealed class StepB : IPipelineStep { public string Name => "B"; }
internal sealed class StepC : IPipelineStep { public string Name => "C"; }
internal sealed class StepD : IPipelineStep { public string Name => "D"; }

/// <summary>
/// Composite over <see cref="IPipelineStep"/> that reports its children in execution order, so tests can
/// assert the exact family composition after edits.
/// </summary>
internal sealed class PipelineComposite : IPipelineStep
{
    public PipelineComposite(IPipelineStep[] steps) => Steps = steps;
    public IPipelineStep[] Steps { get; }
    public string Name => string.Join(",", Steps.Select(step => step.Name));
}
