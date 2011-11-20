using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace FileEncryptor
{
    public class Crypto
    {
        //byte[] ivBytes = Encoding.ASCII.GetBytes("1234567890123456");
        int chunkSize = 256;

        public Crypto()
        {

        }

        public void encryptWithAES(byte[] key, string plainFile, string newEncryptedFile)
        {
            RijndaelManaged aesAlg = new RijndaelManaged();

            aesAlg.KeySize = 256;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.ANSIX923;
            aesAlg.Key = key;
            //aesAlg.IV = ivBytes;

            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            using (FileStream outputStream = File.OpenWrite(newEncryptedFile))
            {
                using (FileStream inputStream = File.OpenRead(plainFile))
                {
                    ICryptoTransform aesEncryptor = aesAlg.CreateEncryptor();

                    outputStream.Write(iv, 0, 16);

                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, aesEncryptor, CryptoStreamMode.Write))
                    {
                        for (long i = 0; i < inputStream.Length; i += chunkSize)
                        {
                            byte[] chunkOData = new byte[chunkSize];

                            int bytesRead = 0;

                            while ((bytesRead = inputStream.Read(chunkOData, 0, chunkSize)) > 0)
                            {
                                /*if (bytesRead != chunkSize)// pad incomplete chunks
                                {
                                    for (int x = bytesRead - 1; x < chunkSize; x++)
                                    {
                                        chunkOData[x] = 0;
                                    }
                                }*/

                                cryptoStream.Write(chunkOData, 0, bytesRead);
                            }
                        }

                        cryptoStream.FlushFinalBlock();
                    }
                }
            }

            aesAlg.Clear();

            /*
            //Encrypt data
            MemoryStream memStream = null;
            CryptoStream cryptoStream = null;

            try
            {
                ICryptoTransform aesEncryptor = aesAlg.CreateEncryptor();

                memStream = new MemoryStream();
                cryptoStream = new CryptoStream(memStream, aesEncryptor, CryptoStreamMode.Write);

                cryptoStream.Write(message, 0, message.Length);
            }
            catch (Exception ee)
            {
                throw ee;
            }
            finally
            {
                if (cryptoStream != null)
                    cryptoStream.Close();
                if (memStream != null)
                    memStream.Close();
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return memStream.ToArray();
             * */
        }

        public void decryptWithAES( byte[] key, string encryptedFile, string newFile)
        {
            
            RijndaelManaged decryptAESAlg = null;

            decryptAESAlg = new RijndaelManaged();
            decryptAESAlg.Key = key;
            //decryptAESAlg.IV = ivBytes;
            decryptAESAlg.Mode = CipherMode.CBC;
            decryptAESAlg.Padding = PaddingMode.ANSIX923;

            using (FileStream inputStream = File.OpenRead(encryptedFile))
            {
                using (FileStream outputStream = File.OpenWrite(newFile))
                {
                    byte[] iv = new byte[16];
                    inputStream.Read(iv, 0, 16);
                    decryptAESAlg.IV = iv;

                    ICryptoTransform decryptor = decryptAESAlg.CreateDecryptor();

                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, decryptor, CryptoStreamMode.Write))
                    {
                        for (long i = 0; i < inputStream.Length; i += chunkSize)
                        {
                            byte[] chunkOData = new byte[chunkSize];
                            int bytesRead = 0;

                            while ((bytesRead = inputStream.Read(chunkOData, 0, chunkSize)) > 0)
                            {
                                cryptoStream.Write(chunkOData, 0, bytesRead);
                            }
                        }
                    }
                }
            }

            decryptAESAlg.Clear();

            /*
            MemoryStream memoryStream = null;
            CryptoStream cryptoStream = null;
            byte[] plaintext = new byte[message.Length];
            byte[] strippedPlainText = null;

            try
            {
                decryptAESAlg = new RijndaelManaged();
                decryptAESAlg.Key = key;
                //decryptAESAlg.IV = iv;
                decryptAESAlg.IV = ivBytes;

                ICryptoTransform decryptor = decryptAESAlg.CreateDecryptor();

                memoryStream = new MemoryStream(message);
                cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

                int length = cryptoStream.Read(plaintext, 0, plaintext.Length);

                strippedPlainText = new byte[length];

                for (int i = 0; i < length; i++)
                {
                    strippedPlainText[i] = plaintext[i];
                }
            }
            catch (Exception ee)
            {
                throw ee;
            }
            finally
            {
                if (cryptoStream != null)
                    cryptoStream.Close();
                if (memoryStream != null)
                    memoryStream.Close();
                if (decryptAESAlg != null)
                    decryptAESAlg.Clear();
            }

            return strippedPlainText;*/

        }
    }
}
