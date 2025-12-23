using System.Security.Cryptography;
using Abblix.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Extension methods for Microsoft.IdentityModel.Tokens interop in tests.
/// These methods convert between Abblix JsonWebKey and Microsoft SecurityKey types.
/// </summary>
public static class MicrosoftInterop
{
	/// <summary>
	/// Converts a JsonWebKey to a SecurityKey used in Microsoft cryptographic operations.
	/// </summary>
	public static SecurityKey ToSecurityKey(this JsonWebKey jsonWebKey)
	{
		return jsonWebKey switch
		{
			RsaJsonWebKey rsaKey => new RsaSecurityKey(rsaKey.ToRsa()) { KeyId = rsaKey.KeyId },
			EllipticCurveJsonWebKey ecKey => new ECDsaSecurityKey(ecKey.ToEcdsa()) { KeyId = ecKey.KeyId },
			OctetJsonWebKey { KeyId: var keyId, KeyValue: {} keyValue } => new SymmetricSecurityKey(keyValue) { KeyId = keyId },
			_ => throw new InvalidOperationException($"Unsupported key type: {jsonWebKey.KeyType}"),
		};
	}

	/// <summary>
	/// Converts a JsonWebKey to SigningCredentials for Microsoft token signing.
	/// </summary>
	public static SigningCredentials ToSigningCredentials(this JsonWebKey jsonWebKey)
		=> new(jsonWebKey.ToSecurityKey(), jsonWebKey.Algorithm);
}
