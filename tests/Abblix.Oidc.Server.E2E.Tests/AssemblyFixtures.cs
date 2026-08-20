// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.E2E.Tests;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Xunit;

// Assembly-level fixtures. Each fixture boots one shared in-memory host and is
// injected into the constructor of every test class that asks for it, regardless
// of which collection the class belongs to. With the per-collection [Collection]
// attributes removed, each test class runs as its own parallel collection, so the
// suite parallelises across classes while still sharing a single host per host
// configuration.
//
// TestFactory drives the default-flow host. Its embedded test license carries no
// client_limit and a single valid_issuers entry (TestConstants.Issuer), so the
// static LicenseChecker never tracks client growth and only ever sees one issuer:
// its ConcurrentDictionary state stays trivial and thread-safe under concurrent
// tests, and the license cannot be lifted into a production host.
//
// NonceEnabledTestFactory is a separate host with RFC 9449 §8 nonce enforcement
// flipped on at the token and UserInfo endpoints; it stays distinct so its
// per-host options never cascade the default-flow tests into the nonce loop.
[assembly: AssemblyFixture(typeof(TestFactory))]
[assembly: AssemblyFixture(typeof(NonceEnabledTestFactory))]
