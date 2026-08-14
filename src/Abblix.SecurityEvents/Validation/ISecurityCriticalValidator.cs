namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// Marks a validation step whose removal or replacement makes accepting a forged or mistyped
/// token possible. The pipeline builder refuses to touch such a step without an explicit,
/// reasoned acknowledgement - "temporarily for a test" must not ride into production silently.
/// </summary>
public interface ISecurityCriticalValidator : ISecurityEventTokenValidator;