// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

namespace Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;

/// <summary>
/// Shared constants for the E2E test suite. Centralising client IDs and the issuer
/// here keeps the static <c>LicenseChecker._knownIssuers</c> /
/// <c>_knownClientIds</c> dictionaries small — the same ID across tests collapses
/// to a single entry. <see cref="LicenseFixture"/> separately removes the
/// FreeLicense numeric ceiling, but the constants reduce noise and keep tests
/// readable when they need to refer to the same client repeatedly.
/// </summary>
public static class TestConstants
{
    /// <summary>
    /// The single canonical issuer used by every E2E test. Matches the
    /// UnitTests convention so logs / certificates / cached JWKS line up.
    /// </summary>
    public const string Issuer = "https://auth.example.com";

    /// <summary>
    /// Pre-seeded confidential client with RAR enabled
    /// (<c>authorization_details_types = ["payment_initiation"]</c>),
    /// id_token RAR-emission toggle off (default). Baseline RAR scenarios.
    /// </summary>
    public const string ConfidentialClientId = "e2e-confidential";

    /// <summary>Same as <see cref="ConfidentialClientId"/> but with
    /// <c>ForceAuthorizationDetailsInIdentityToken = true</c>.</summary>
    public const string IdTokenRarClientId = "e2e-idtoken-rar";

    /// <summary>Client with empty allowlist — every RAR request is rejected.</summary>
    public const string EmptyAllowlistClientId = "e2e-empty-allowlist";

    /// <summary>Client with <c>null</c> allowlist — no per-client constraint
    /// (only the per-type validator gates).</summary>
    public const string UnrestrictedClientId = "e2e-unrestricted";

    /// <summary>Shared secret across every pre-seeded client.</summary>
    public const string ConfidentialClientSecret = "e2e-secret";

    /// <summary>The single canonical redirect_uri.</summary>
    public const string RedirectUri = "https://client.example.com/cb";

    /// <summary>RFC 9396 §2.2 type for PSD2-style payment initiation.</summary>
    public const string PaymentInitiationType = "payment_initiation";

    /// <summary>RFC 9396 §2.2 type used for negative tests (no registered validator).</summary>
    public const string AccountInformationType = "account_information";
}
