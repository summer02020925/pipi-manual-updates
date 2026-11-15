using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

public sealed class UpdateManifest {
    public Version Version { get; internal set; }
    public long Sequence { get; internal set; }
    public DateTime ExpiresUtc { get; internal set; }
    public Uri PackageUri { get; internal set; }
    public string Sha256 { get; internal set; }
    public long Size { get; internal set; }
}

// No network, subprocesses, settings writes or production keys belong in this class.
public static class UpdateCore {
    public const long MaxPackageBytes = 32L * 1024 * 1024;
    public const long MaxExpandedBytes = 64L * 1024 * 1024;
    public const long MaxFileBytes = 32L * 1024 * 1024;
    static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    static readonly string[] RequiredFiles = {
        "PipiManual.exe", "Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll",
        "WebView2Loader.dll", "PipiManual.exe.config", "WebView2-LICENSE.txt", "WebView2-NOTICE.txt"
    };
    public static string[] PackageFiles { get { return (string[])RequiredFiles.Clone(); } }

    public static UpdateManifest VerifyEnvelope(byte[] envelopeUtf8, RSAParameters trustedPublicKey,
        Version currentVersion, long minimumSequence, DateTime utcNow, ISet<string> allowedPackageHosts) {
        return VerifyEnvelopeCore(envelopeUtf8,trustedPublicKey,currentVersion,minimumSequence,utcNow,allowedPackageHosts,true);
    }
    // ONLY for authenticating an already accepted installed release. Never use this
    // method to select, download or accept a new update. Expiry is acquisition policy,
    // not a kill switch for a previously installed application.
    public static UpdateManifest VerifyInstalledEnvelope(byte[] envelopeUtf8, RSAParameters trustedPublicKey,
        ISet<string> allowedPackageHosts) {
        return VerifyEnvelopeCore(envelopeUtf8,trustedPublicKey,new Version(0,0,0,0),0,DateTime.UtcNow,allowedPackageHosts,false);
    }
    static UpdateManifest VerifyEnvelopeCore(byte[] envelopeUtf8, RSAParameters trustedPublicKey,
        Version currentVersion, long minimumSequence, DateTime utcNow, ISet<string> allowedPackageHosts, bool enforceFreshness) {
        if (envelopeUtf8 == null || envelopeUtf8.Length == 0 || envelopeUtf8.Length > 32768) throw Invalid("Envelope size");
        if (currentVersion == null || minimumSequence < 0 || allowedPackageHosts == null || allowedPackageHosts.Count == 0) throw Invalid("Trust configuration");
        var envelope = FlatJson.Parse(Utf8.GetString(envelopeUtf8));
        ExactKeys(envelope, "payload", "signature");
        byte[] payload = DecodeCanonicalBase64(Text(envelope,"payload"));
        byte[] signature = DecodeCanonicalBase64(Text(envelope,"signature"));
        if (payload.Length == 0 || payload.Length > 8192) throw Invalid("Payload size");
        if (trustedPublicKey.Modulus == null || trustedPublicKey.Modulus.Length < 256 || trustedPublicKey.Modulus.Length > 512 || signature.Length != trustedPublicKey.Modulus.Length) throw Invalid("Signature/key size");
        using (RSA rsa = RSA.Create()) {
            rsa.ImportParameters(trustedPublicKey);
            if (!rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) throw Invalid("Signature verification failed");
        }
        var m = FlatJson.Parse(Utf8.GetString(payload));
        ExactKeys(m,"appId","channel","architecture","version","sequence","expiresUtc","packageUrl","sha256","size");
        if (Text(m,"appId") != "PipiManualFresh" || Text(m,"channel") != "stable" || Text(m,"architecture") != "x64") throw Invalid("Wrong application/channel/architecture");
        string versionText = Text(m,"version");
        if (!Regex.IsMatch(versionText, @"^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$")) throw Invalid("Version format");
        Version version;
        if (!Version.TryParse(versionText,out version) || (enforceFreshness && version.CompareTo(currentVersion) <= 0)) throw Invalid("Not a newer version");
        long sequence = Number(m,"sequence"), size = Number(m,"size");
        if (sequence <= minimumSequence) throw Invalid("Sequence rollback/replay");
        if (size <= 0 || size > MaxPackageBytes) throw Invalid("Package size");
        DateTime expiry;
        if (!DateTime.TryParseExact(Text(m,"expiresUtc"),"yyyy-MM-dd'T'HH:mm:ss'Z'",CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal,out expiry) || (enforceFreshness && expiry <= utcNow.ToUniversalTime())) throw Invalid("Expired/invalid manifest");
        string url = Text(m,"packageUrl"); Uri uri;
        if (url.Length > 2048 || !Uri.TryCreate(url,UriKind.Absolute,out uri) || uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || !allowedPackageHosts.Any(h=>string.Equals(h,uri.DnsSafeHost,StringComparison.OrdinalIgnoreCase))) throw Invalid("Package URL not trusted");
        string hash = Text(m,"sha256");
        if (!Regex.IsMatch(hash,"^[0-9a-f]{64}$")) throw Invalid("SHA256 format");
        return new UpdateManifest { Version=version, Sequence=sequence, ExpiresUtc=expiry, PackageUri=uri, Sha256=hash, Size=size };
    }
    public static void VerifyPackage(string path, UpdateManifest manifest) {
        using (var stream = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) VerifyStream(stream,manifest);
    }
    static void VerifyStream(Stream stream, UpdateManifest manifest) {
        if (manifest == null || manifest.Size <= 0 || manifest.Size > MaxPackageBytes || stream.Length != manifest.Size) throw Invalid("Package length mismatch");
        byte[] actual;
        using (var sha = SHA256.Create()) actual = sha.ComputeHash(stream);
        string hex = BitConverter.ToString(actual).Replace("-","").ToLowerInvariant();
        if (!string.Equals(hex,manifest.Sha256,StringComparison.Ordinal)) throw Invalid("Package hash mismatch");
        stream.Position=0;
    }
    // stageDirectory must be a NEW dedicated directory under the updater's trusted root.
    // The same held read-only file handle is hashed and extracted, avoiding path-swap TOCTOU.
    public static string[] StagePackage(string zipPath, UpdateManifest manifest, string stageDirectory) {
        string fullStage=Path.GetFullPath(stageDirectory);
        if (Directory.Exists(fullStage) || File.Exists(fullStage)) throw Invalid("Stage already exists");
        RejectReparseAncestors(Path.GetDirectoryName(fullStage));
        bool created=false;
        try {
            using (var file=new FileStream(zipPath,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                VerifyStream(file,manifest);
                using (var archive=new ZipArchive(file,ZipArchiveMode.Read,true)) {
                    ValidateArchive(archive);
                    Directory.CreateDirectory(fullStage); created=true;
                    foreach(var e in archive.Entries) {
                        string dest=Path.Combine(fullStage,e.FullName);
                        using(var input=e.Open()) using(var output=new FileStream(dest,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                            byte[] buffer=new byte[65536];long count=0;int read;
                            while((read=input.Read(buffer,0,buffer.Length))>0) {
                                count=checked(count+read); if(count>e.Length || count>MaxFileBytes)throw Invalid("Expanded entry exceeds declared size");
                                output.Write(buffer,0,read);
                            }
                            if(count!=e.Length)throw Invalid("Expanded entry truncated");
                            output.Flush(true);
                        }
                    }
                }
            }
            return RequiredFiles.Select(n=>Path.Combine(fullStage,n)).ToArray();
        } catch {
            if(created) { try { Directory.Delete(fullStage,true); } catch { /* Caller may report staging cleanup failure. */ } }
            throw;
        }
    }
    static void ValidateArchive(ZipArchive archive) {
        if (archive.Entries.Count != RequiredFiles.Length) throw Invalid("Unexpected archive entry count");
        var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long total=0;
        foreach(var e in archive.Entries) {
            string name=e.FullName;
            if (!RequiredFiles.Contains(name,StringComparer.Ordinal) || !seen.Add(name) || name.IndexOfAny(new[]{'/', '\\', ':', '\0'})>=0) throw Invalid("Unexpected/duplicate archive path");
            int mode=(e.ExternalAttributes>>16)&0xF000;
            if (mode!=0 && mode!=0x8000) throw Invalid("Archive entry is not a regular file");
            if ((e.ExternalAttributes & (int)(FileAttributes.ReparsePoint | FileAttributes.Directory))!=0) throw Invalid("Archive reparse entry");
            if (e.Length <= 0 || e.Length > MaxFileBytes || e.CompressedLength <= 0) throw Invalid("Archive entry size");
            total=checked(total+e.Length); if(total>MaxExpandedBytes)throw Invalid("Archive expansion limit");
        }
    }
    public static void VerifyInstalled(string zipPath, UpdateManifest manifest, string directory) {
        string root=Path.GetFullPath(directory);
        if(!Directory.Exists(root))throw Invalid("Installed directory missing");
        RejectReparseAncestors(root);
        var actual=Directory.GetFileSystemEntries(root);
        if(actual.Length!=RequiredFiles.Length || actual.Any(p=>!RequiredFiles.Contains(Path.GetFileName(p),StringComparer.Ordinal)))throw Invalid("Installed file list differs");
        using(var file=new FileStream(zipPath,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            VerifyStream(file,manifest);
            using(var archive=new ZipArchive(file,ZipArchiveMode.Read,true)) {
                ValidateArchive(archive);
                foreach(var e in archive.Entries) {
                    string installed=Path.Combine(root,e.FullName);
                    if((File.GetAttributes(installed)&(FileAttributes.ReparsePoint|FileAttributes.Directory))!=0)throw Invalid("Installed entry is not regular");
                    using(var expected=e.Open()) using(var source=new FileStream(installed,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                        if(source.Length!=e.Length)throw Invalid("Installed file length differs");
                        byte[] x=HashExactLength(expected,e.Length),y=HashExactLength(source,e.Length);
                        int different=x.Length^y.Length;for(int i=0;i<x.Length&&i<y.Length;i++)different|=x[i]^y[i];
                        if(different!=0)throw Invalid("Installed file hash differs");
                    }
                }
            }
        }
    }
    static byte[] HashExactLength(Stream stream,long length) {
        using(var sha=SHA256.Create()) {
            byte[] buffer=new byte[65536];long total=0;int read;
            while((read=stream.Read(buffer,0,buffer.Length))>0) {
                total=checked(total+read);if(total>length || total>MaxFileBytes)throw Invalid("Entry exceeds declared size");
                sha.TransformBlock(buffer,0,read,buffer,0);
            }
            if(total!=length)throw Invalid("Entry is truncated");
            sha.TransformFinalBlock(new byte[0],0,0);return sha.Hash;
        }
    }
    static void RejectReparseAncestors(string path) {
        for(var d=new DirectoryInfo(path);d!=null;d=d.Parent) {
            if(d.Exists && (d.Attributes & FileAttributes.ReparsePoint)!=0)throw Invalid("Reparse ancestor");
        }
    }
    static byte[] DecodeCanonicalBase64(string value) {
        if(value.Length==0 || value.Any(char.IsWhiteSpace))throw Invalid("Base64 format");
        byte[] data;try{data=Convert.FromBase64String(value);}catch(FormatException){throw Invalid("Base64 format");}
        if(Convert.ToBase64String(data)!=value)throw Invalid("Noncanonical base64");return data;
    }
    static void ExactKeys(Dictionary<string,object> d,params string[] keys) {if(d.Count!=keys.Length || keys.Any(k=>!d.ContainsKey(k)))throw Invalid("Manifest/envelope fields");}
    static string Text(Dictionary<string,object>d,string key){object v; if(!d.TryGetValue(key,out v)||!(v is string))throw Invalid("Expected text field");return(string)v;}
    static long Number(Dictionary<string,object>d,string key){object v;if(!d.TryGetValue(key,out v)||!(v is long))throw Invalid("Expected integer field");return(long)v;}
    static InvalidDataException Invalid(string reason){return new InvalidDataException(reason);}

    // Deliberately limited JSON grammar: object with unique keys, string or unsigned integer
    // scalar values only. Rejects duplicate keys, loose parsing, nesting and unknown schemas.
    static class FlatJson {
        public static Dictionary<string,object> Parse(string json){return new Reader(json).Read();}
        sealed class Reader {
            readonly string s;int p;
            public Reader(string value){s=value;}
            void White(){while(p<s.Length && (s[p]==' '||s[p]=='\r'||s[p]=='\n'||s[p]=='\t'))p++;}
            void Need(char c){White();if(p>=s.Length||s[p++]!=c)throw Invalid("JSON syntax");}
            string Str(){
                Need('"');var b=new StringBuilder();bool ended=false;
                while(p<s.Length){char c=s[p++];if(c=='"'){ended=true;break;}if(c<32)throw Invalid("JSON control character");
                    if(c=='\\'){if(p>=s.Length)throw Invalid("JSON escape");c=s[p++];switch(c){
                        case '"':case '\\':case '/':b.Append(c);break;
                        case 'b':b.Append('\b');break;case 'f':b.Append('\f');break;case 'n':b.Append('\n');break;case 'r':b.Append('\r');break;case 't':b.Append('\t');break;
                        case 'u':if(p+4>s.Length)throw Invalid("JSON unicode");int v;if(!int.TryParse(s.Substring(p,4),NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture,out v))throw Invalid("JSON unicode");b.Append((char)v);p+=4;break;
                        default:throw Invalid("JSON escape");}
                    }else b.Append(c);
                }
                if(!ended)throw Invalid("JSON unterminated string");string value=b.ToString();Utf8.GetBytes(value);return value;
            }
            public Dictionary<string,object> Read(){
                var d=new Dictionary<string,object>(StringComparer.Ordinal);Need('{');White();
                if(p<s.Length&&s[p]=='}'){p++;}else while(true){
                    string key=Str();Need(':');White();object value;
                    if(p<s.Length&&s[p]=='"')value=Str();else{
                        int start=p;while(p<s.Length&&s[p]>='0'&&s[p]<='9')p++;
                        string n=s.Substring(start,p-start);long number;
                        if(n.Length==0||(n.Length>1&&n[0]=='0')||!long.TryParse(n,NumberStyles.None,CultureInfo.InvariantCulture,out number))throw Invalid("JSON integer");value=number;
                    }
                    if(d.ContainsKey(key))throw Invalid("Duplicate JSON key");d.Add(key,value);White();
                    if(p<s.Length&&s[p]=='}'){p++;break;}Need(',');
                }
                White();if(p!=s.Length)throw Invalid("Trailing JSON data");return d;
            }
        }
    }
}
