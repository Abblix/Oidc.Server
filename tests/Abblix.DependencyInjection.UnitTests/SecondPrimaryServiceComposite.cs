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
/// A second composite over the same interface, so a test can compose a family twice under two different
/// composite types - the shape a guard asking about the composite rather than about the family lets past.
/// </summary>
internal sealed class SecondPrimaryServiceComposite : IPrimaryService
{
    private readonly IPrimaryService[] _inner;
    public SecondPrimaryServiceComposite(IPrimaryService[] inner) => _inner = inner;
    public string GetValue() => string.Join("|", _inner.Select(x => x.GetValue()));
}