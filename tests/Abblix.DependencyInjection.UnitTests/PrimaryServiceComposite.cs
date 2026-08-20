// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Linq;
using Abblix.DependencyInjection.UnitTests.Model;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Composite over <see cref="IPrimaryService"/> with the public array-accepting constructor that
/// <see cref="ServiceCollectionExtensions.Compose{TInterface,TComposite}"/> discovers by reflection.
/// Declared internal (like the production composites) so the same-assembly ActivatorUtilities path resolves it.
/// </summary>
internal sealed class PrimaryServiceComposite : IPrimaryService
{
    private readonly IPrimaryService[] _inner;
    public PrimaryServiceComposite(IPrimaryService[] inner) => _inner = inner;
    public string GetValue() => string.Join(",", _inner.Select(x => x.GetValue()));
}