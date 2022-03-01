#include <Arduino.h>
#include <SD.h>


class AWS_S3 {
    static String _bucket;
 private:
    static String canonicalUnsignedRequest(String req, String path, int length) {

    static canonicalRequest(String req, String path, const byte payload[], int length) {

 public:
    static int setup(String bucket);
    static int put(String path, File payload);
    static int put(String path, const byte payload[], int length);
};
    
