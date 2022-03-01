#include <SD.h>

extern "C++" {
    class AWS_S3 {
    public:
        static int put(String path, File payload);
        static int put(String path, const byte payload[], int length);
    };
    
}
