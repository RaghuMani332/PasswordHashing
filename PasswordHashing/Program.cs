using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        // User's password to be hashed
        string password = "userpassword";

        // Generate a random salt
        byte[] salt = GenerateSalt();
        Console.WriteLine("--------------------------------------------------");
        foreach (var item in salt)
        {
            Console.WriteLine(item);
        }
        Console.WriteLine("------------------------------------------------------");
        // Combine the password and salt
        byte[] saltedPassword = Combine(Encoding.UTF8.GetBytes(password), salt);

        // Hash the salted password
        byte[] hashedPassword = Hash(saltedPassword);

        // Convert the hashed password and salt to Base64 strings for storage
        string hashedPasswordBase64 = Convert.ToBase64String(hashedPassword);
        string saltBase64 = Convert.ToBase64String(salt);

        // Store hashedPasswordBase64 and saltBase64 in the database
        Console.WriteLine("Hashed Password: " + hashedPasswordBase64);
        Console.WriteLine("Salt: " + saltBase64);

        // Decode Base64 strings back into byte arrays (for demonstration purposes)
        byte[] decodedHashedPassword = Convert.FromBase64String(hashedPasswordBase64);
        byte[] decodedSalt = Convert.FromBase64String(saltBase64);

        // Print decoded byte arrays (for demonstration purposes)
        Console.WriteLine("Decoded Hashed Password: " + BitConverter.ToString(decodedHashedPassword).Replace("-", ""));
        Console.WriteLine("Decoded Salt: " + BitConverter.ToString(decodedSalt).Replace("-", ""));
    }

    static byte[] GenerateSalt()
    {
        byte[] salt = new byte[16];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
        }
        return salt;
    }

    static byte[] Combine(byte[] password, byte[] salt)
    {
        byte[] combined = new byte[password.Length + salt.Length];
        Buffer.BlockCopy(password, 0, combined, 0, password.Length);
        Buffer.BlockCopy(salt, 0, combined, password.Length, salt.Length);
        return combined;
    }

    static byte[] Hash(byte[] data)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(data);
        }
    }
}
