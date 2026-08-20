// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Shared fixtures for the RFC 9396 Rich Authorization Requests scenario classes.
/// The RAR suite is split by concern into <see cref="RichAuthorizationRequestsTests"/>
/// (round-trip + validation), <see cref="RarMetadataTests"/> (discovery / DCR /
/// licensing / introspection) and <see cref="RarConsentTests"/> (consent narrowing
/// + refresh) so each runs as its own parallel xunit collection. The
/// <c>payment_initiation</c> request payload is the common vocabulary across all
/// three, so it lives here; group-specific payloads stay on the concrete classes.
/// </summary>
public abstract class RarTestBase(TestFactory factory) : TestBase(factory)
{
    protected const string PaymentInitiationWireJson =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";
}
