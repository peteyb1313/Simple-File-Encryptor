using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using Microsoft.Win32;
using System.Security.Cryptography;
using System.IO;
using System.Xml;
using System.Reflection;
using System.Drawing;
using System.ComponentModel;

namespace FileEncryptor
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        //List<String> workingFiles = new List<string>();
        String SECURE_FILE_EXTENSION = ".simp";
        String salt = "!@%&*!#$^Bunnies!#%^@";
        int NUMBER_OF_HASHES = 15000;

        public MainWindow()
        {
            InitializeComponent();


            string[] args = Environment.GetCommandLineArgs();

            if (args.Length > 1)
            {
                if (args[1] != null)
                {
                    string file = args[1];

                    if (file.EndsWith(SECURE_FILE_EXTENSION, true, System.Globalization.CultureInfo.CurrentCulture))
                    {
                        tabItem2.Focus();
                        listBoxFilesToDecrypt.Items.Add(file);
                        buttonDecrypt.IsEnabled = true;
                    }
                    else
                    {
                        listBoxFilesToEncrypt.Items.Add(file);
                        buttonEncrypt.IsEnabled = true;
                    }
                }
            }
        }

        private void buttonAddFiles_Click(object sender, RoutedEventArgs e)
        {
            string[] files = browseFiles();
            foreach (string file in files)
            {
                if (!listBoxFilesToEncrypt.Items.Contains(file) && file != "")
                {
                    listBoxFilesToEncrypt.Items.Add(file);

                    if (buttonEncrypt.IsEnabled == false)
                        buttonEncrypt.IsEnabled = true;
                }
            }
        }

        private string[] browseFiles()
        {
            Microsoft.Win32.OpenFileDialog fileDialogue = new Microsoft.Win32.OpenFileDialog();
            fileDialogue.Title = "Encrypt files...";
            fileDialogue.Filter = "All Files (*.*)|*";
            fileDialogue.Multiselect = true;

            fileDialogue.ShowDialog();

            return fileDialogue.FileNames;
        }

        private string getFolder()
        {
            System.Windows.Forms.FolderBrowserDialog folderDialogue = new System.Windows.Forms.FolderBrowserDialog();
            folderDialogue.Description = "Select Output Folder";
            folderDialogue.ShowNewFolderButton = true;
            folderDialogue.ShowDialog();

            return folderDialogue.SelectedPath;
        }

        private void buttonRemove_Click(object sender, RoutedEventArgs e)
        {
            if(listBoxFilesToEncrypt.SelectedIndex != -1)
                listBoxFilesToEncrypt.Items.RemoveAt(listBoxFilesToEncrypt.SelectedIndex);
        }

        private void buttonEncrypt_Click(object sender, RoutedEventArgs e)
        {
        
            String password = textBoxPassword.Text;
            String outputFolder = "";
            String error = "";
            

            if (listBoxFilesToEncrypt.Items.Count < 1)
            {
                error += "Please select at least one file to encrypt.\n";
            }

            if (password == null || password == "")
            {
                error += "Please enter a password.\n";
            }

            if (password.Length < 6)
            {
                error += "Password must be at least 6 characters long.\n";
            }

            if (error != "")
            {
                MessageBox.Show(error, "Error", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            SHA256 sha = SHA256.Create();

            byte[] key = sha.ComputeHash(Encoding.UTF8.GetBytes(password + salt));

            for (int i = 0; i < NUMBER_OF_HASHES; i++)
                key = sha.ComputeHash(key);

            if (checkBoxSelectOutputDir.IsChecked.Value)
            {
                outputFolder = getFolder() + "\\";
                if (outputFolder == "\\")
                    return;
            }

            Crypto crypto = new Crypto();

            foreach (string file in listBoxFilesToEncrypt.Items)
            {
                string newOutputFolder = "";
                /*byte[] data = readFile(file);
                
                if (data == null)
                {
                    if (MessageBox.Show("There was an error reading " + file + "\n\nContinue encrypting files?", "Read Error", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                        continue;
                    else
                        return;
                }*/

                String fileName = file.Substring(file.LastIndexOf("\\") + 1, file.Length - file.LastIndexOf("\\") - 1);
                outputFolder = outputFolder.Trim();
                fileName = fileName.Trim();

                if (checkBoxSelectOutputDir.IsChecked.Value == false)
                    newOutputFolder = file.Substring(0, file.LastIndexOf("\\") + 1);
                else
                    newOutputFolder = outputFolder;

                string newFile = newOutputFolder + fileName + SECURE_FILE_EXTENSION;

                try
                {
                    crypto.encryptWithAES(key, file, newFile);
                }
                catch (Exception ee)
                {
                    if (MessageBox.Show("There was an error encrypting the file: " + fileName + "\n" + ee.ToString() + "\n\nContinue encrypting files? (the original will not be deleted)", "Error", MessageBoxButton.YesNo, MessageBoxImage.Error) == MessageBoxResult.No)
                        return;
                    else
                        continue;
                }

                
                /*try
                {
                    writeNewFile(encryptedData, newOutputFolder, fileName + SECURE_FILE_EXTENSION, hint);
                }
                catch (Exception ee)
                {
                    if (MessageBox.Show("There was an error writing the encrypted file: " + fileName + "\n" + ee.ToString() + "\n\nContinue? (the original will not be deleted)", "Error", MessageBoxButton.YesNo, MessageBoxImage.Error) == MessageBoxResult.No)
                        return;
                    else
                        continue;
                }*/

                if (checkBoxDeleteAfter.IsChecked.Value)
                {
                    //delete file
                    File.Delete(file);
                }
            }

            bool exit = false;

            if (MessageBox.Show("Operation Completed!\n\nExit?", "Success", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                exit = true;
            }

            if (checkBoxSelectOutputDir.IsChecked.Value)
            {
                string windir = Environment.GetEnvironmentVariable("WINDIR");
                System.Diagnostics.Process prc = new System.Diagnostics.Process();
                prc.StartInfo.FileName = windir + @"\explorer.exe";
                prc.StartInfo.Arguments = outputFolder;
                prc.Start();
            }

            if (exit)
                this.Close(); 
        }

        /*private void writeNewFile(byte[] contents, String outputLocation, String fileName, String hint)
        {
            //MessageBox.Show("Writing " + outputLocation + fileName);

            XmlDocument doc = new XmlDocument();

            XmlNode node = doc.CreateNode(XmlNodeType.XmlDeclaration, "", "");
            doc.AppendChild(node);

            XmlElement element = doc.CreateElement("SimpleEncryptionFile");

            XmlAttribute attyAlg = doc.CreateAttribute("algorithm");
            attyAlg.InnerText = "AES-256";

            XmlAttribute attyName = doc.CreateAttribute("fileName");
            attyName.InnerText = fileName;

            XmlAttribute attyHint = doc.CreateAttribute("hint");
            attyHint.InnerText = hint;

            element.Attributes.Append(attyAlg);
            element.Attributes.Append(attyName);
            element.Attributes.Append(attyHint);

            XmlText innerds = doc.CreateTextNode(Convert.ToBase64String(contents));

            element.AppendChild(innerds);

            doc.AppendChild(element);

            doc.Save(outputLocation + fileName);

        }*/

        /*private byte[] readFile(string currentFile)
        {
            FileStream fileStream = null;
            BinaryReader binReader = null;
            byte[] fileContents = null;

            try
            {
                fileStream = new FileStream(currentFile, FileMode.Open, FileAccess.Read);
                binReader = new BinaryReader(fileStream);

                int length = (int)new FileInfo(currentFile).Length;

                fileContents = new byte[length];

                fileContents = binReader.ReadBytes(length); //read the entire file into a buffer.
            }
            catch (FileNotFoundException fnfe)
            {
                MessageBox.Show(fnfe.Message, "File Not Found", MessageBoxButton.OK, MessageBoxImage.Error);
                fileContents = null;
            }
            catch (IOException ioe)
            {
                MessageBox.Show(ioe.Message, "Could Not Read File", MessageBoxButton.OK, MessageBoxImage.Error);
                fileContents = null;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "General Error", MessageBoxButton.OK, MessageBoxImage.Error);
                fileContents = null;
            }
            finally
            {
                if (fileStream != null)
                    fileStream.Close();
                if (binReader != null)
                    binReader.Close();
            }

            return fileContents;
        }*/

        private void buttonAddFilesDecrypt_Click(object sender, RoutedEventArgs e)
        {
            string[] files = browseFilesDecrypt();

            foreach (string file in files)
            {
                if (file != "")
                {
                    if (!listBoxFilesToDecrypt.Items.Contains(file))
                    {
                        listBoxFilesToDecrypt.Items.Add(file);

                        if (buttonDecrypt.IsEnabled == false)
                            buttonDecrypt.IsEnabled = true;
                    }
                }
            }
        }

        private void buttonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            String password = textBoxPasswordDecrypt.Text;
            byte[] key;
            String error = "";

            String outputFolder = "";

            if (listBoxFilesToDecrypt.Items.Count < 1)
            {
                error += "Please select at least one file to decrypt.\n";
            }

            if (password == null || password == "")
            {
                error += "Please enter a password.\n";
            }

            if (password.Length < 6)
            {
                error += "Password must be at least 6 characters long.\n";
            }

            if (checkBoxRunAfterDecrypt.IsChecked.Value == true)
            {
                if (listBoxFilesToDecrypt.Items.Count > 1)
                {
                    error += "If you want to run the file after decrypt you can only decrypt a single file.\n";
                }
            }

            if (error != "")
            {
                MessageBox.Show(error, "Error", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }


            SHA256 sha = SHA256.Create();

            key = sha.ComputeHash(Encoding.UTF8.GetBytes(password + salt));

            for (int i = 0; i < NUMBER_OF_HASHES; i++)
                key = sha.ComputeHash(key);

            if (checkBoxSelectOutputDirDecrypt.IsChecked.Value == true)
            {
                outputFolder = getFolder() + "\\";
                if (outputFolder == "\\")
                    return;
            }
            
            string fileToRun = "";

            foreach (string file in listBoxFilesToDecrypt.Items)
            {
                
                String oldFileName = file.Substring(file.LastIndexOf("\\") + 1, file.Length - file.LastIndexOf("\\") - 1);
                String newFileName = oldFileName.Replace(".simp", "");

                string newOutDir= "";

                /* try
                {
                    clearData = parseAndDecrypt(file, key, out newFileName);
                }
                catch (Exception ee)
                {
                    //error reading file
                    if(MessageBox.Show("Error reading " +file +"\n" +ee.Message +"\n\nContinue Decrypting Files? (original will not be deleted)", "Error", MessageBoxButton.YesNo, MessageBoxImage.Error) == MessageBoxResult.No)
                        return;
                    else
                        continue;
                }*/

                if (checkBoxSelectOutputDirDecrypt.IsChecked.Value == false)
                {
                    newOutDir = file.Substring(0, file.LastIndexOf("\\") + 1);
                }
                else
                {
                    newOutDir = outputFolder;
                }

                String newFile = newOutDir + newFileName;

                fileToRun = newFile;

                Crypto crypto = new Crypto();

                try
                {
                    crypto.decryptWithAES(key, file, newFile);
                    //writeNewFileAfterDecrypt(clearData, newOutDir + newFileName);
                }
                catch (Exception ee)
                {
                    if (MessageBox.Show("Error Decrypting " +oldFileName +"\n" +ee.ToString() +"\n\nContinue Decrypting Files? (original will not be deleted)", "Error Writing", MessageBoxButton.YesNo, MessageBoxImage.Error) == MessageBoxResult.No)
                        return;
                    else
                        continue;
                }

                if (checkBoxDeleteAfterDecrypt.IsChecked.Value)
                {
                    //delete file
                    File.Delete(file);
                }
            }

            bool exit = false;

            if (MessageBox.Show("Operation Completed!\n\nExit?", "Success", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                exit = true;
            }


            if (checkBoxSelectOutputDirDecrypt.IsChecked.Value == true)
            {
                string windir = Environment.GetEnvironmentVariable("WINDIR");
                System.Diagnostics.Process prc = new System.Diagnostics.Process();
                prc.StartInfo.FileName = windir + @"\explorer.exe";
                prc.StartInfo.Arguments = outputFolder;
                prc.Start();
            }

            if (checkBoxRunAfterDecrypt.IsChecked.Value == true)
            {
                System.Diagnostics.Process.Start(fileToRun);
            }

            if (exit)
                this.Close();

        }

        private void writeNewFileAfterDecrypt(byte[] data, string path)
        {
            FileStream fileStream = null;

            try
            {
                fileStream = new FileStream(path, FileMode.Create, FileAccess.Write);

                fileStream.Write(data, 0, data.Length);
            }
            catch
            {
                throw new Exception("Error writing new file " + path);
            }
            finally
            {
                if (fileStream != null)
                {
                    fileStream.Flush();
                    fileStream.Close();
                }
            }

        }

        /*private byte[] parseAndDecrypt(string file, byte[] key, out string fileName)
        {
            XmlDocument doc = new XmlDocument();

            doc.Load(file);

            XmlNode node = doc.ChildNodes[1];

            if (node.Name != "SimpleEncryptionFile")
                throw new Exception("Wrong XML node name");

            

            try
            {
                fileName = node.Attributes["fileName"].Value;
            }
            catch 
            {
                throw new Exception("Bad file attributes");
            }

            fileName = fileName.Replace(".simp", "");

            string innerDataStr = node.InnerText;

            byte[] innerData = Convert.FromBase64String(innerDataStr);

            Crypto crypto = new Crypto();

            byte[] clearData;

            try
            {
                clearData = crypto.decryptWithAES(innerData, key);
            }
            catch
            {
                throw new Exception("Error Decrypting file");
            }

            if(clearData == null)
                throw new Exception("Error Decrypting file");

            return clearData;
        }*/

        private void buttonRemoveDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxFilesToDecrypt.SelectedIndex != -1)
                listBoxFilesToDecrypt.Items.RemoveAt(listBoxFilesToDecrypt.SelectedIndex);
        }

        private string[] browseFilesDecrypt()
        {
            Microsoft.Win32.OpenFileDialog fileDialogue = new Microsoft.Win32.OpenFileDialog();
            fileDialogue.Title = "Decrypt files...";
            fileDialogue.Filter = "Simply Encrypted Files (*.simp)|*.simp";
            fileDialogue.Multiselect = true;

            fileDialogue.ShowDialog();

            return fileDialogue.FileNames;
        }
    }
}
