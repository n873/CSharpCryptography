using CSharpCryptography.Rc2;
using CSharpCryptography.Shared;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CSharpCryptography.Test
{
    [TestClass]
    public class Rc2Test : BaseEncryptionAttributes
    {
        public Rc2Test()
        {
            using (var myRijndael = new RijndaelManaged())
            {
                myRijndael.GenerateKey();
                myRijndael.GenerateIV();
                Key = myRijndael.Key;
                IV = myRijndael.IV;
            }
        }

        [TestMethod]
        public void EncryptString() {
            var encrypted = Rc2Utility.EncryptStringToBytes_Rc2(originalText, Key, IV);

            Assert.AreNotEqual(originalText, encrypted.ToString());
        }

        [TestMethod]
        public void DecryptString() {
            var encrypted = Rc2Utility.EncryptStringToBytes_Rc2(originalText, Key, IV);
            var decryptedString = Rc2Utility.DecryptStringFromBytes_Rc2(encrypted, Key, IV);

            Assert.AreEqual(originalText, decryptedString);
        }
    }
}
