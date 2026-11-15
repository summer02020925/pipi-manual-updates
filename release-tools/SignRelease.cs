using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

internal static class SignRelease {
    // Private key is provided only by the repository Actions secret environment variable, never argv or a file.
    static int Main(string[] args) {
        string privateXml=null;RSA signer=null;string stage=null;
        try {
            if(args.Length!=7)throw new Exception();
            string zip=Path.GetFullPath(args[0]),version=args[1],url=args[3],publicFile=args[4],output=args[5],expiry=args[6];
            long sequence;if(!long.TryParse(args[2],NumberStyles.None,CultureInfo.InvariantCulture,out sequence)||sequence<=0)throw new Exception();
            if(!Regex.IsMatch(version,@"^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$"))throw new Exception();
            var expected=new Uri("https://github.com/summer02020925/pipi-manual-updates/releases/download/v"+version+"/PipiManualFresh-"+version+"-win-x64.zip");
            if(url!=expected.AbsoluteUri)throw new Exception();
            DateTime expires;if(!DateTime.TryParseExact(expiry,"yyyy-MM-dd'T'HH:mm:ss'Z'",CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal,out expires)||expires<=DateTime.UtcNow||expires>DateTime.UtcNow.AddDays(181))throw new Exception();
            var length=new FileInfo(zip).Length;if(length<=0||length>UpdateCore.MaxPackageBytes)throw new Exception();
            string digest;using(var sha=SHA256.Create())using(var input=File.OpenRead(zip))digest=BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();
            var manifest=new UpdateManifest{Version=Version.Parse(version),Sequence=sequence,ExpiresUtc=expires,PackageUri=expected,Sha256=digest,Size=length};
            stage=Path.Combine(Path.GetTempPath(),"pipi-release-verify-"+Guid.NewGuid().ToString("N"));
            UpdateCore.StagePackage(zip,manifest,stage);
            var name=AssemblyName.GetAssemblyName(Path.Combine(stage,"PipiManual.exe"));
            if(name.Name!="PipiManual"||name.Version!=manifest.Version||name.ProcessorArchitecture!=ProcessorArchitecture.Amd64)throw new Exception();
            var assembly=Assembly.ReflectionOnlyLoadFrom(Path.Combine(stage,"PipiManual.exe"));
            var config=assembly.GetType("UpdateConfiguration",true);
            var compiledKey=(string)config.GetField("PublicKeyXml",BindingFlags.Public|BindingFlags.Static).GetRawConstantValue();
            var compiledFeed=(string)config.GetField("ManifestUrl",BindingFlags.Public|BindingFlags.Static).GetRawConstantValue();
            var compiledRepo=(string)config.GetField("RepositoryPath",BindingFlags.Public|BindingFlags.Static).GetRawConstantValue();
            if(compiledFeed!="https://github.com/summer02020925/pipi-manual-updates/releases/latest/download/manifest.json"||compiledRepo!="/summer02020925/pipi-manual-updates")throw new Exception();
            var publicXml=File.ReadAllText(publicFile);
            if(publicXml.Contains("<D>")||publicXml.Contains("<P>")||publicXml.Contains("<Q>"))throw new Exception();
            using(var trusted=RSA.Create())using(var embedded=RSA.Create()) {
                trusted.FromXmlString(publicXml);embedded.FromXmlString(compiledKey);
                var trustedParts=trusted.ExportParameters(false);if(!Same(trustedParts,embedded.ExportParameters(false)))throw new Exception();
                privateXml=Environment.GetEnvironmentVariable("PIPI_UPDATE_SIGNING_KEY_XML");
                Environment.SetEnvironmentVariable("PIPI_UPDATE_SIGNING_KEY_XML",null);
                if(string.IsNullOrEmpty(privateXml))throw new Exception();
                signer=RSA.Create();var csp=signer as RSACryptoServiceProvider;if(csp!=null)csp.PersistKeyInCsp=false;signer.FromXmlString(privateXml);privateXml=null;
                if(!Same(trustedParts,signer.ExportParameters(false)))throw new Exception();
                var payload=new Dictionary<string,object>{{"appId","PipiManualFresh"},{"channel","stable"},{"architecture","x64"},{"version",version},{"sequence",sequence},{"expiresUtc",expiry},{"packageUrl",url},{"sha256",digest},{"size",length}};
                var json=new JavaScriptSerializer();var bytes=new UTF8Encoding(false).GetBytes(json.Serialize(payload));
                var signature=signer.SignData(bytes,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                var envelope=new UTF8Encoding(false).GetBytes(json.Serialize(new Dictionary<string,string>{{"payload",Convert.ToBase64String(bytes)},{"signature",Convert.ToBase64String(signature)}}));
                UpdateCore.VerifyEnvelope(envelope,trustedParts,new Version(0,0,0,0),0,DateTime.UtcNow,new HashSet<string>{"github.com"});
                File.WriteAllBytes(output,envelope);
            }
            Console.WriteLine("Signed manifest created and verified. No private key was written.");return 0;
        } catch {Console.Error.WriteLine("Release signing/validation failed. No release was published; private details suppressed.");return 1;}
        finally {Environment.SetEnvironmentVariable("PIPI_UPDATE_SIGNING_KEY_XML",null);privateXml=null;if(signer!=null)signer.Dispose();if(stage!=null)try{Directory.Delete(stage,true);}catch{}}
    }
    static bool Same(RSAParameters a,RSAParameters b) {return Convert.ToBase64String(a.Modulus)==Convert.ToBase64String(b.Modulus)&&Convert.ToBase64String(a.Exponent)==Convert.ToBase64String(b.Exponent);}
}
