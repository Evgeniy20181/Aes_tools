using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

public class Program {
    
    static void Main(string[] args) {
        Console.WriteLine("Starting AES encryption/decryption tool!");
        Stopwatch timer = new Stopwatch();

        string password;
        do
        {
            Console.Write("Enter a password (at least 8 characters): ");
            password = Console.ReadLine() ?? string.Empty;

            if (password.Length < 8)
            {
                Console.WriteLine("Password must be at least 8 characters long. Please try again.");
            }
        } while (password.Length < 8);
        while (true){
        Console.WriteLine("\n\n\n\n\n\n");
        Console.WriteLine("Select an action:");
        Console.WriteLine("1. Encrypt a file");
        Console.WriteLine("2. Decrypt a file");
        Console.Write("Enter the action number: ");
        string? action = Console.ReadLine();

        Console.Write("Enter the file path: ");
        string? filePath = Console.ReadLine();

        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            Console.WriteLine("Invalid file path!");
            continue;
        }

        string outputFilePath = Aes_tools.GenerateOutputFilePath(filePath, action);
        timer.Start();
        if (action == "1")
        {
            Console.WriteLine("Encrypting the file...");
            try {
            Aes_tools.EncryptFile(filePath, outputFilePath,password);
            }
            catch (Exception ex) { Console.WriteLine(ex.Message);}
            Console.WriteLine($"File encrypted: {outputFilePath}");
        }
        else if (action == "2")
        {
            Console.WriteLine("Decrypting the file...");
            try{
            Aes_tools.DecryptFile(filePath, outputFilePath,password);
            }
            catch (Exception ex) { Console.WriteLine(ex.Message);}
            Console.WriteLine($"File decrypted: {outputFilePath}");
        }
        else
        {
            Console.WriteLine("Invalid action selection!");
        }
        timer.Stop();
        Console.WriteLine($"Time used: {timer.Elapsed}");
        Console.WriteLine($"Time used: {timer.ElapsedMilliseconds} ms");
        }
    }
}



static class Aes_tools {

    const Int32 pbkdf2_iter = 700000;

    //Encrypt data
    internal static byte[]? Encrypt (Aes aes, string data) {
        byte[] result = [];
        try {
            var encryptor = aes.CreateEncryptor();
            Console.WriteLine("Encryptor saved!");
        
            using(MemoryStream memoryStream = new MemoryStream()) {
                // Create crypto stream using the CryptoStream class. This class is the key to encryption
                // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream
                // to encrypt
                Console.WriteLine("RAM Alocated!");
                using(CryptoStream CryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)) {
                    // Create StreamWriter and write data to a Crypto stream
                    using(StreamWriter streamWriter = new StreamWriter(CryptoStream)) {
                        streamWriter.Write(data);
                    }
                }
                result = memoryStream.ToArray();//get data from RAM
            }
            return result;
        }
        catch (Exception e) {
            Console.WriteLine ("[ERROR] " + e.Message);
            return null;
        }
    }


//Decrypt data
    internal static string? Decrypt (Aes aes, byte[] data) {
        string result;

        try {
            var encryptor = aes.CreateDecryptor();
            Console.WriteLine("Decryptor saved!");
            using(MemoryStream memoryStream = new MemoryStream(data)) {
                // Create crypto stream using the CryptoStream class. This class is the key to encryption
                // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream
                // to encrypt
                Console.WriteLine("RAM Alocated!");
                using(CryptoStream CryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Read)) {
                    // Create StreamWriter and write data to a Crypto stream
                    using(StreamReader streamReader = new StreamReader(CryptoStream)) {
                        result = streamReader.ReadToEnd();//get data from RAM
                    }
                }
            }
            return result;
        }
        catch (Exception e) {
            Console.WriteLine ("[ERROR] " + e.Message);
            return null;
        }
    }
internal static void EncryptFile(string inputFilePath, string outputFilePath, string password)
{
    using (Aes aes = Aes.Create())
    {
        // Generate salt and IV
        byte[] salt = GenerateSalt(16);
        aes.GenerateIV();  // Generate a new IV for this encryption
        aes.Key = DeriveKey(password, salt, pbkdf2_iter, 32);
        Console.WriteLine("[INFO] File AES key: " + Convert.ToBase64String(aes.Key));

        using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
        {
            // Write Salt (16 bytes) and IV (16 bytes) to the file
            outputFileStream.Write(salt, 0, salt.Length);
            outputFileStream.Write(aes.IV, 0, aes.IV.Length);

            using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
            using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            {
                inputFileStream.CopyTo(cryptoStream);
                cryptoStream.FlushFinalBlock();
            }
        }
    }
}

internal static void DecryptFile(string inputFilePath, string outputFilePath, string pass)
{
    using (FileStream inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
    {
        // Read Salt (16 bytes) and IV (16 bytes) from the file
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];

        inputFileStream.Read(salt, 0, salt.Length);
        inputFileStream.Read(iv, 0, iv.Length);

        using (Aes aes = Aes.Create())
        {
            aes.Key = DeriveKey(pass, salt, pbkdf2_iter, 32);
            aes.IV = iv;

            Console.WriteLine("[INFO] File AES key: " + Convert.ToBase64String(aes.Key));

            using (FileStream outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
            {
                cryptoStream.CopyTo(outputFileStream); // Keep the file input stream for decryption
            }
        }
    }
}
    // Load settings
    internal static byte[] GenerateSalt(int length)
    {
        using (var rng = RandomNumberGenerator.Create())  // Microsoft crypto generator
        {
            byte[] salt = new byte[length];
            rng.GetBytes(salt);  // Fill with random bytes
            return salt;
        }
    }

    internal static byte[] DeriveKey(string password, byte[] salt, int iterations, int keyLength)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
        {
            return pbkdf2.GetBytes(keyLength);
        }
    }


    internal static string GenerateOutputFilePath(string originalFilePath, string? action)
    {
        string directory = Path.GetDirectoryName(originalFilePath) ?? string.Empty;
        string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(originalFilePath);
        string extension = Path.GetExtension(originalFilePath);

        string suffix = action == "1" ? "_encrypted" : "_decrypted";
        return Path.Combine(directory, $"{fileNameWithoutExtension}{suffix}{extension}");
    }
}

/*
  byte[]? test = Aes_tools.Encrypt(myAes, original);
                if (test != null && test.Length > 0) {
                    Console.WriteLine("Cryptert: "+Convert.ToBase64String(test));
                    //Decrypting
                    string? decrypted = Aes_tools.Decrypt(myAes, test);
                    if (decrypted != null && decrypted.Length > 0) {
                        Console.WriteLine("Decrypted: "+decrypted);
                    }
                    else {
                        Console.WriteLine("Decryption feil!");
                    }
                }
                else {
                    Console.WriteLine("Feil!");
                }

*/