#include "HTTPClient.h"
#include "mbedtls/md.h"
#include <time.h>
#include <TimeLib.h>

#include <esp32-aws-s3.h>
#include <SD_MMC.h>


String sha256(const byte* payload, unsigned int len)
{
    byte shaResult[32];
    String r;
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *) payload, len);
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);
  
    for(int i= 0; i< sizeof(shaResult); i++){
        char str[3];

        sprintf(str, "%02x", (int)shaResult[i]);
        Serial.print(str);
        r += String(str);
    }
    return r;
}


String hmac256(const byte *key, int keylen, const byte* payload, int len)
{
    byte shaResult[32];
    String r;
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, key, keylen);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *) payload, len);
    mbedtls_md_hmac_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);
  
    for(int i= 0; i< sizeof(shaResult); i++){
        char str[3];

        sprintf(str, "%02x", (int)shaResult[i]);
        r += String(str);
    }

    return r;

}

void fromHex(String s, byte* b)
{
    for (int i = 0; i < 32; i++) {
        byte c = s.c_str()[2*i];
        c = c > '9' ? (c -'a' + 10) : (c-'0');
        byte d = s.c_str()[2*i + 1];
        d = d > '9' ? (d -'a' + 10) : (d-'0');
      
        b[i] = (byte) (c * 16 + d);
    }
}

String dateHeader;

String canonicalRequest(String req, String path, const byte payload[], int length) {

    unsigned long t = now();

    char buf1[20];

    sprintf(buf1, "%04d%02d%02dT%02d%02d%02dZ",  year(t),month(t), day(t), hour(t), minute(t), second(t));

    String filename = path;
  
    String hash = sha256(payload, length);
    Serial.println(hash); 
    dateHeader = buf1;
  
    String r = req +"\n"; 
    r += filename + "\n";		/* CanonicalURI */
    r += String("\n");		/* CanonicalQueryString */
    r += String("host:" BUCKET "\n");		/* CanonicalHeaders */
    r += String("x-amz-content-sha256:") + hash + "\n";
    r += String( "x-amz-date:") + dateHeader + "\n";
    r += "\n";
    r += String("host;x-amz-content-sha256;x-amz-date\n");		/* SignedHeaders */
    r += sha256(payload, length);

    return r;
}

String canonicalUnsignedRequest(String req, String path, int length) {

    unsigned long t = now();

    char buf1[20];

    sprintf(buf1, "%04d%02d%02dT%02d%02d%02dZ",  year(t),month(t), day(t), hour(t), minute(t), second(t));

    String filename = path;
  
    dateHeader = buf1;
  
    String r = req +"\n"; 
    r += filename + "\n";		/* CanonicalURI */
    r += String("\n");		/* CanonicalQueryString */
    r += String("host:" BUCKET "\n");		/* CanonicalHeaders */
    r += String("x-amz-content-sha256:") + "UNSIGNED-PAYLOAD" + "\n";
    r += String( "x-amz-date:") + dateHeader + "\n";
    r += "\n";
    r += String("host;x-amz-content-sha256;x-amz-date\n");		/* SignedHeaders */
    r += "UNSIGNED-PAYLOAD";

    return r;
}



String toSign(String msg)
{
    unsigned long t = now();
    char buf1[20];
    char buf2[20];
    sprintf(buf1, "%04d%02d%02dT%02d%02d%02dZ",  year(t),month(t), day(t), hour(t), minute(t), second(t));
    sprintf(buf2, "%04d%02d%02d",  year(t),month(t), day(t));

    String sts = "AWS4-HMAC-SHA256\n";

    sts += buf1;
    sts += "\n";
  
    sts += buf2;
    sts += "/eu-west-2/s3/aws4_request\n"  ;
    
    sts += sha256((const byte*)msg.c_str(), strlen(msg.c_str()));
    return sts;
  
}

String signKey()
{
    unsigned long t = now();
    char buf1[20];
    char buf2[20];
    sprintf(buf1, "%04d%02d%02dT%02d%02d%02dZ",  year(t),month(t), day(t), hour(t), minute(t), second(t));
    sprintf(buf2, "%04d%02d%02d",  year(t),month(t), day(t));

    byte h1[32];
    byte h2[32];
    byte h3[32];
    const char* region = "eu-west-2";
    const char* service = "s3";
    const char* req = "aws4_request";
    const char * secret_key = "AWS4" SECRET_KEY;
    Serial.println(secret_key);
    String hex1 = hmac256((const byte*)(secret_key), strlen(secret_key), (const byte*)buf2, strlen(buf2));
    fromHex(hex1, h1);
    String hex2 = hmac256(h1, 32, (byte*)region, strlen(region));
    Serial.println(hex2);
    fromHex(hex2, h2);
    String hex3 = hmac256(h2, 32, (byte*)service, strlen(service));
    Serial.println(hex3);
    fromHex(hex3, h3);
    return hmac256(h3, 32, (byte*)req, strlen(req));
}

String sign(String key, String msg) {
    byte b[32];
    fromHex(key, b);
    return hmac256(b, 32, (const byte*) msg.c_str(), msg.length());
}

String auth(String sig) {
  
    unsigned long t = now();

    char buf2[20];
    sprintf(buf2, "%04d%02d%02d",  year(t),month(t), day(t));
  
    String ah = "AWS4-HMAC-SHA256 ";
    ah += "Credential=" ACCESS_KEY;
    ah += "/";
    ah += buf2;
    ah += "/eu-west-2/s3/aws4_request, ";
    ah += "SignedHeaders=host;x-amz-content-sha256;x-amz-date, ";
    ah += "Signature=";
    ah += sig;
    return ah;
}

int AWS_S3::put(String path, const byte payload[], int length)
{

    String can = canonicalRequest(String("PUT"), path, payload, length);
    String sts = toSign(can);
    String skey = signKey();
  

    Serial.print("Can: ");
    Serial.println(can);
    Serial.print("String to Sign: ");
    Serial.println(sts);
    Serial.print("Signing Key: ");
    Serial.println(skey);
    Serial.print("Signed:");
    Serial.println(sign(skey, sts));
    HTTPClient http;
    http.begin(String("http://net.lecomber.cctv.s3.eu-west-2.amazonaws.com") + path);
    http.addHeader("Authorization", auth(sign(skey, sts)));
    http.addHeader("x-amz-content-sha256", sha256(payload, length));
    http.addHeader("x-amz-date", dateHeader);
    http.sendRequest("PUT", (unsigned char*)payload, length);

    Serial.println(http.getString());
    return -1;
    
}

#define PAYLOAD_MAX 8192
byte transferBuff[PAYLOAD_MAX];

int AWS_S3::put(String path, File payload)
{
    
    
    String can = canonicalUnsignedRequest(String("PUT"), path, payload.size());
    String sts = toSign(can);
    String skey = signKey();

    Serial.print("Can: ");
    Serial.println(can);
    Serial.print("String to Sign: ");
    Serial.println(sts);
    Serial.print("Signing Key: ");
    Serial.println(skey);
    Serial.print("Signed:");
    Serial.println(sign(skey, sts));

    Serial.print("Length: ");
    Serial.println(payload.size());
    
    HTTPClient http;
    http.begin(String("http://net.lecomber.cctv.s3.eu-west-2.amazonaws.com") + path);
    http.addHeader("Authorization", auth(sign(skey, sts)));
    http.addHeader("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
    http.addHeader("x-amz-date", dateHeader);
    Serial.println("Sending.. " );

    if (payload.size() > 0) {
        http.sendRequest("PUT", &payload, payload.size());
    }
    Serial.print("File sent: ");
    Serial.println(path);

    return -1;
    
}


