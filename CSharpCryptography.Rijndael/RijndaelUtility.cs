using System;
using System.IO;
using System.Security.Cryptography;

namespace CSharpCryptography.Rijndael
{
    public static class RijndaelUtility
    {
        public static byte[] EncryptStringToBytes_Rijndael(string plainText, byte[] key, byte[] iv)
        {
            // check arguments
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");
            byte[] encrypted;

            // create an rc2 object with the specified key and iv
            using (var rijAlg = System.Security.Cryptography.Rijndael.Create())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                // create an encryptor to perform the stream transform
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // create the streams used for encryption
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Write all data to the stream
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            //Return the encrypted bytes from the memory stream
            return encrypted;
        }

        public static string DecryptStringFromBytes_Rijndael(byte[] cipherText, byte[] key, byte[] iv)
        {
            // check arguments
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");

            // declare the string used to hold the decrypted
            string plainText = null;

            // create an rijndael object with the specified key and iv
            using (var rijAlg = System.Security.Cryptography.Rijndael.Create())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                // create a decryptor to perform the stream transform
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // create the streams used for decryption
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // read the decrypted bytes from the decrypting stream and place them in a string
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }

                return plainText;
            }
        }
    }
}
