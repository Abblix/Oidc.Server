// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Threading;

namespace Abblix.DependencyInjection.UnitTests.Model;

public class ServiceA : IPrimaryService, IAliasService
{
    private static int _instanceCounter;
    private readonly int _instanceId;

    public ServiceA()
    {
        _instanceId = Interlocked.Increment(ref _instanceCounter);
    }

    public string GetValue() => $"ServiceA-{_instanceId}";
}
