using System;
using System.Text;
using System.Text.Json;
using Abblix.Jwt;

var key = new RsaJsonWebKey
{
    KeyId = "rsa-key-1",
    Usage = "sig",
    Algorithm = "RS256",
    Exponent = Encoding.UTF8.GetBytes("AQAB"),
    Modulus = Encoding.UTF8.GetBytes("modulus-value"),
};

var json = JsonSerializer.Serialize(key, new JsonSerializerOptions
{
    PropertyNamingPolicy = null,
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = true,
});

Console.WriteLine(json);
