#include <Arduino.h>
#include <SD.h>


class AWS_S3 {
    static String _bucket;
    static String _access_key;
    static String _secret_key;
 private:
    static String canonicalUnsignedRequest(String req, String path, int length) ;

    static String signKey();
    static String auth(String sig);

    static String canonicalRequest(String req, String path, const byte payload[], int length);

 public:
    static void setup(String access_key, String secret_key, String bucket);
    static int put(String path, File payload);
    static int put(String path, const byte payload[], int length);
};
    
