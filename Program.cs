using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Deployment.Internal.CodeSigning;
using System.IO;

namespace XMLSignature
{
    class Program
    {
        private static string SIGNATURE_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        private static string SIGNATURE_DIG = "http://www.w3.org/2001/04/xmlenc#sha256";
        private static string CERT_FILE = "somecertificate.pfx";
        public static void Main(String[] args)
        {
            try
            {
                CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), SIGNATURE_ALG);

                // Generate a signing key.
                RSACryptoServiceProvider Key = new RSACryptoServiceProvider();

                // Create an XML file to sign.
                CreateSomeXml("Example.xml");

                // Sign the XML that was just created and save it in a 
                // new file.
                SignXmlFile("Example.xml", "signedExample.xml", Key);
                    
                // Use below to use certificate.

                // Verify the signature of the signed XML.
                bool result = VerifyXmlFile("SignedExample.xml", Key);

                // Display the results of the signature verification to 
                // the console.
                if (result)
                {
                    Console.WriteLine("The XML signature is valid.");
                }
                else
                {
                    Console.WriteLine("The XML signature is not valid.");
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }
        }

        // Sign an XML file and save the signature in a new file. This method does not  
        // save the public key within the XML file.  This file cannot be verified unless  
        // the verifying code has the key with which it was signed.
        public static void SignXmlFile(string FileName, string SignedFileName, RSA Key)
        {
            // Create a new XML document.
            XmlDocument doc = new XmlDocument();

            // Load the passed XML file using its name.
            doc.Load(new XmlTextReader(FileName));

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(doc);

            // Add the key to the SignedXml document using ceritificate file. 
            //X509Certificate2 certificate;
            //using (FileStream fs =
            //       File.Open(CERT_FILE, FileMode.Open))
            //using (BinaryReader br = new BinaryReader(fs))
            //{
            //    certificate =
            //        new X509Certificate2(
            //           br.ReadBytes((int)br.BaseStream.Length), "demo");
            //}
            //signedXml.SigningKey = certificate.PrivateKey;

            // Add the key to the SignedXml document using pre-shared key. 
            signedXml.SigningKey = Key;
            signedXml.SignedInfo.SignatureMethod = SIGNATURE_ALG;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.            
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = SIGNATURE_DIG;

            // If you are using certificate, use code below, 
            // and pass the certificate as parameter.
            //KeyInfo keyInfo = new KeyInfo();
            //KeyInfoX509Data keyInfoData = new KeyInfoX509Data(certificate);
            //keyInfo.AddClause(keyInfoData);
            //signedXml.KeyInfo = keyInfo;

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            // Save the signed XML document to a file specified
            // using the passed string.
            XmlTextWriter xmltw = new XmlTextWriter(SignedFileName, new UTF8Encoding(false));
            doc.WriteTo(xmltw);
            xmltw.Close();
        }
        
        // Verify the signature of an XML file against an asymetric 
        // algorithm and return the result.
        public static Boolean VerifyXmlFile(String Name, RSA Key)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document. 
            xmlDocument.Load(Name);

            // Create a new SignedXml object and pass it
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            return signedXml.CheckSignature(Key);
        }

        // Verify the signature of an XML file from its certificate 
        // in the signature key info.
        public static Boolean VerifyXmlFileFromCert(String Name)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document. 
            xmlDocument.Load(Name);

            SignedXml signedXml = new SignedXml(xmlDocument);

            // Load the signature node.
            signedXml.LoadXml((XmlElement)xmlDocument.GetElementsByTagName("Signature")[0]);

            // Get certificate key info from XML
            X509Certificate2 certificate = null;
            foreach (KeyInfoClause clause in signedXml.KeyInfo)
            {
                if (clause is KeyInfoX509Data)
                {
                    if (((KeyInfoX509Data)clause).Certificates.Count > 0)
                    {
                        certificate =
                        (X509Certificate2)((KeyInfoX509Data)clause).Certificates[0];
                    }
                }
            }

            // Check the signature and return the result.
            return signedXml.CheckSignature(certificate, true);
        }

        // Create example data to sign.
        public static void CreateSomeXml(string FileName)
        {
            // Create a new XmlDocument object.
            XmlDocument document = new XmlDocument();

            // Create a new XmlNode object.
            XmlNode node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");
            // Append the node to the document.
            document.AppendChild(node);

            // Save the XML document to the file name specified.
            XmlTextWriter xmltw = new XmlTextWriter(FileName, new UTF8Encoding(false));
            document.WriteTo(xmltw);
            xmltw.Close();
        }
    }
}
