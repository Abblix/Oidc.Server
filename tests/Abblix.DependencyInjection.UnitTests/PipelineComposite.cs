// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Linq;

namespace Abblix.DependencyInjection.UnitTests;

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