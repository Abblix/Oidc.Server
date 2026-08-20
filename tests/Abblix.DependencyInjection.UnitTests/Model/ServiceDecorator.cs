// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.DependencyInjection.UnitTests.Model;

public class ServiceDecorator(IBaseService inner) : IBaseService
{
	public IBaseService Inner => inner;

	public string GetValue() => $"Decorated:{inner.GetValue()}";
}
