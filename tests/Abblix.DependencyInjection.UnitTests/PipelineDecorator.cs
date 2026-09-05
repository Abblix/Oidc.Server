// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>Wraps whatever answers <see cref="IPipelineStep"/>, so a test can decorate a composed family.</summary>
internal sealed class PipelineDecorator(IPipelineStep inner) : IPipelineStep
{
    public string Name => $"[{inner.Name}]";
}